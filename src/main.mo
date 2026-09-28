import Map "mo:map/Map";
import { nhash; phash; thash } "mo:map/Map";
import Result "mo:base/Result";
import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Char "mo:base/Char";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Float "mo:base/Float";
import Int "mo:base/Int";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Time "mo:base/Time";
import Error "mo:base/Error";
import Random "mo:base/Random";
import Json "mo:json";
import HttpTypes "mo:http-types";
import Sha256 "mo:sha2/Sha256";
import Base16 "mo:base16/Base16";

import Mcp "mo:mcp-motoko-sdk/mcp/Mcp";
import McpTypes "mo:mcp-motoko-sdk/mcp/Types";
import AuthTypes "mo:mcp-motoko-sdk/auth/Types";
import ApiKey "mo:mcp-motoko-sdk/auth/ApiKey";
import AuthState "mo:mcp-motoko-sdk/auth/State";
import AuthCleanup "mo:mcp-motoko-sdk/auth/Cleanup";
import HttpHandler "mo:mcp-motoko-sdk/mcp/HttpHandler";
import SrvTypes "mo:mcp-motoko-sdk/server/Types";
import Cleanup "mo:mcp-motoko-sdk/mcp/Cleanup";
import State "mo:mcp-motoko-sdk/mcp/State";
import HttpAssets "mo:mcp-motoko-sdk/mcp/HttpAssets";
import Beacon "mo:mcp-motoko-sdk/mcp/Beacon";

shared ({ caller = deployer }) persistent actor class McpServer() = self {

  // --- DATA MODEL ---
  //
  // An OWNER (any principal with a key here) names AGENTS and gives them
  // GRANTS. An agent is either ISSUED — this canister derives a principal for
  // it and mints an API key bound to that principal, so the owner never hands
  // an agent their own key — or LINKED, an existing principal the owner names.
  //
  // A grant is one of two kinds:
  //
  //   #spend   ENFORCED. The owner approves one ICRC-2 allowance to this
  //            canister; agents pay only through `pay`, which checks the grant
  //            and only then calls icrc2_transfer_from(owner -> recipient).
  //   #action  DECLARED. A named permission ("contract.sign") with optional
  //            limits. Agents record uses with `use_permission`; any caller
  //            can ask `check_permission` before trusting an agent.
  //
  // Every grant expires. Limits reset on calendar periods in UTC.
  //
  // Money invariants (see SPEC.md):
  //   1. `from` is always the grant's owner — no tool takes a `from`.
  //   2. A payment's amount is reserved against the budget BEFORE the ledger
  //      await, and released only when the ledger says it did not move.
  //   3. The owner's allowance is the ceiling, and the ledger enforces it.

  type Period = { #day; #week; #month; #total };

  type AgentStatus = { #active; #paused; #removed };

  type Agent = {
    id : Nat;
    owner : Principal;
    name : Text;
    principal : Principal;
    issued : Bool;
    keyHash : ?Text; // issued agents only: the SDK key-store entry
    status : AgentStatus;
    createdAt : Int;
  };

  type Account = { owner : Principal; subaccount : ?Blob };

  type Recipient = { label_ : Text; account : Account };

  type Asset = { ledger : Text; symbol : Text; decimals : Nat8 };

  type GrantKind = {
    #spend : { asset : Asset; recipients : [Recipient]; anyRecipient : Bool };
    #action : { action : Text; unit : ?Text; counterparties : [Principal] };
  };

  type Usage = { periodKey : Int; amount : Nat; uses : Nat };

  type Grant = {
    id : Nat;
    owner : Principal;
    agentId : Nat;
    kind : GrantKind;
    purpose : Text;
    perUseMax : ?Nat; // minor units (spend) or hundredths (action)
    budget : ?Nat; // per period, same units
    maxUses : ?Nat; // per period
    period : Period;
    expiresAt : Int;
    createdAt : Int;
    revokedAt : ?Int;
    usage : Usage;
    lifetimeAmount : Nat;
    lifetimeUses : Nat;
    lastUsedAt : ?Int;
  };

  type PaymentStatus = {
    #pending; // a ledger call is in flight
    #sent : Nat; // ledger block index
    #failed : Text; // the ledger refused; nothing moved, budget released
    #uncertain : Text; // the call threw; money may have moved, budget kept
  };

  type Payment = {
    id : Nat;
    grantId : Nat;
    owner : Principal;
    agentId : Nat;
    to : Account;
    toLabel : ?Text;
    amount : Nat;
    note : ?Text;
    requestId : ?Text;
    periodKey : Int;
    status : PaymentStatus;
    at : Int;
  };

  type Event = {
    at : Int;
    agentId : ?Nat;
    grantId : ?Nat;
    kind : Text;
    ok : Bool;
    detail : Text;
  };

  type AllowedAsset = { symbol : Text; decimals : Nat8; capMinor : Nat };

  // --- LIMITS ---

  transient let nanosPerDay : Int = 86_400_000_000_000;
  transient let maxAgentsPerOwner : Nat = 25;
  transient let maxActiveGrantsPerOwner : Nat = 50;
  transient let maxGrantsPerOwner : Nat = 500;
  transient let maxRecipients : Nat = 20;
  transient let maxCounterparties : Nat = 20;
  transient let maxEventsPerOwner : Nat = 300;
  transient let maxNameChars : Nat = 60;
  transient let maxLabelChars : Nat = 60;
  transient let maxPurposeChars : Nat = 200;
  transient let maxNoteChars : Nat = 200;
  transient let maxActionChars : Nat = 60;
  transient let maxUnitChars : Nat = 12;
  transient let maxRequestIdChars : Nat = 64;
  transient let defaultExpiryDays : Nat = 30;
  transient let maxExpiryDays : Nat = 366;
  transient let actionDecimals : Nat = 2;
  transient let budgetCapMultiple : Nat = 10; // period budget cap = 10 x per-payment cap

  // --- STATE ---

  var nextAgentId : Nat = 1;
  var nextGrantId : Nat = 1;
  var nextPaymentId : Nat = 1;
  let agentsById : Map.Map<Nat, Agent> = Map.new();
  let agentIdsByOwner : Map.Map<Principal, [Nat]> = Map.new();
  // A linked principal can be an agent for several owners.
  let agentIdsByPrincipal : Map.Map<Principal, [Nat]> = Map.new();
  // Principals this canister issued. Nobody holds their private key.
  let issuedPrincipals : Map.Map<Principal, Nat> = Map.new();
  let grantsById : Map.Map<Nat, Grant> = Map.new();
  let grantIdsByOwner : Map.Map<Principal, [Nat]> = Map.new();
  let grantIdsByAgent : Map.Map<Nat, [Nat]> = Map.new();
  let paymentsById : Map.Map<Nat, Payment> = Map.new();
  let paymentByRequest : Map.Map<Text, Nat> = Map.new();
  let eventsByOwner : Map.Map<Principal, [Event]> = Map.new();

  // Only allowlisted ledgers, as in Escrow: a free-text ledger id would let an
  // owner point a grant at a hostile canister of their own.
  transient let ckusdcLedger : Text = "xevnm-gaaaa-aaaar-qafnq-cai";
  let allowedAssets : Map.Map<Text, AllowedAsset> = Map.new();
  Map.set(allowedAssets, thash, ckusdcLedger, { symbol = "ckUSDC"; decimals = 6 : Nat8; capMinor = 1_000_000_000 });

  // --- MCP SERVER PLUMBING ---

  var stable_http_assets : HttpAssets.StableEntries = [];
  transient let http_assets = HttpAssets.init(stable_http_assets);

  let appContext : McpTypes.AppContext = State.init([]);
  let authContext : AuthTypes.AuthContext = AuthState.initApiKey(deployer);

  Cleanup.startCleanupTimer<system>(appContext);
  AuthCleanup.startCleanupTimer<system>(authContext);

  // Prometheus usage beacon — reports anonymized usage to the tracker canister.
  transient let beaconContext : Beacon.BeaconContext = Beacon.init(
    Principal.fromText("m63pw-fqaaa-aaaai-q33pa-cai"),
    ?(15 * 60),
  );
  Beacon.startTimer<system>(beaconContext);

  // --- ICRC LEDGER INTERFACE ---

  type TransferFromArgs = {
    spender_subaccount : ?Blob;
    from : Account;
    to : Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };

  type TransferFromError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #InsufficientAllowance : { allowance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };

  type TransferFromResult = { #Ok : Nat; #Err : TransferFromError };

  type AllowanceArgs = { account : Account; spender : Account };
  type Allowance = { allowance : Nat; expires_at : ?Nat64 };

  func ledgerOf(id : Text) : actor {
    icrc1_balance_of : (Account) -> async Nat;
    icrc1_fee : () -> async Nat;
    icrc2_allowance : (AllowanceArgs) -> async Allowance;
    icrc2_transfer_from : (TransferFromArgs) -> async TransferFromResult;
  } {
    actor (id);
  };

  // --- CALENDAR MATH ---
  //
  // Days are days-since-epoch; the civil <-> days conversion is Howard
  // Hinnant's algorithm, which relies on division truncating toward zero
  // exactly as Motoko's Int division does.

  func floorDiv(a : Int, b : Int) : Int {
    let q = a / b;
    if (a % b != 0 and ((a < 0) != (b < 0))) q - 1 else q;
  };

  func floorMod(a : Int, b : Int) : Int { a - floorDiv(a, b) * b };

  func daysFromCivil(y0 : Int, m : Int, d : Int) : Int {
    let y = if (m <= 2) y0 - 1 else y0;
    let era = (if (y >= 0) y else y - 399) / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = floorMod(m + 9, 12); // March = 0
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468;
  };

  func civilFromDays(z0 : Int) : (Int, Int, Int) {
    let z = z0 + 719468;
    let era = (if (z >= 0) z else z - 146096) / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if (mp < 10) mp + 3 else mp - 9; // [1, 12]
    (if (m <= 2) y + 1 else y, m, d);
  };

  func pad2(n : Int) : Text {
    let a = Int.abs(n);
    if (a < 10) "0" # Nat.toText(a) else Nat.toText(a);
  };

  func fmtDate(days : Int) : Text {
    let (y, m, d) = civilFromDays(days);
    Int.toText(y) # "-" # pad2(m) # "-" # pad2(d);
  };

  func fmtUtc(at : Int) : Text {
    let day = floorDiv(at, nanosPerDay);
    let minute = floorDiv(at - day * nanosPerDay, 60_000_000_000);
    fmtDate(day) # " " # pad2(minute / 60) # ":" # pad2(minute % 60) # " UTC";
  };

  // Periods are calendar periods in UTC. Weeks start Monday: day 0
  // (1970-01-01) was a Thursday, so day -3 is the Monday of week 0.

  func periodKey(p : Period, at : Int) : Int {
    let days = floorDiv(at, nanosPerDay);
    switch (p) {
      case (#day) days;
      case (#week) floorDiv(days + 3, 7);
      case (#month) { let (y, m, _) = civilFromDays(days); y * 12 + (m - 1) };
      case (#total) 0;
    };
  };

  func periodEnd(p : Period, key : Int) : ?Int {
    switch (p) {
      case (#day) ?((key + 1) * nanosPerDay);
      case (#week) ?(((key + 1) * 7 - 3) * nanosPerDay);
      case (#month) {
        let n = key + 1;
        ?(daysFromCivil(floorDiv(n, 12), floorMod(n, 12) + 1, 1) * nanosPerDay);
      };
      case (#total) null;
    };
  };

  func periodText(p : Period) : Text {
    switch (p) { case (#day) "day"; case (#week) "week"; case (#month) "month"; case (#total) "total" };
  };

  func periodPhrase(p : Period) : Text {
    switch (p) { case (#day) "today"; case (#week) "this week"; case (#month) "this month"; case (#total) "in total" };
  };

  // --- TEXT PARSING ---

  func digitsToNat(t : Text) : ?Nat {
    if (t.size() == 0) return null;
    var acc : Nat = 0;
    for (c in t.chars()) {
      if (not Char.isDigit(c)) return null;
      acc := acc * 10 + Nat32.toNat(Char.toNat32(c) - 48);
    };
    ?acc;
  };

  func lower(t : Text) : Text {
    Text.map(
      t,
      func(c : Char) : Char {
        let n = Char.toNat32(c);
        if (n >= 65 and n <= 90) Char.fromNat32(n + 32) else c;
      },
    );
  };

  func splitParts(t : Text, sep : Char) : [Text] {
    Buffer.toArray(
      do {
        let out = Buffer.Buffer<Text>(4);
        for (piece in Text.split(t, #char sep)) out.add(piece);
        out;
      }
    );
  };

  /// "YYYY-MM-DD" -> days since epoch.
  func parseDate(t : Text) : ?Int {
    let parts = splitParts(Text.trim(t, #char ' '), '-');
    if (parts.size() != 3) return null;
    let ?y = digitsToNat(parts[0]) else return null;
    let ?m = digitsToNat(parts[1]) else return null;
    let ?d = digitsToNat(parts[2]) else return null;
    if (y < 2020 or y > 2100 or m < 1 or m > 12 or d < 1 or d > 31) return null;
    let days = daysFromCivil(y, m, d);
    let (ry, rm, rd) = civilFromDays(days);
    if (ry != y or rm != m or rd != d) return null;
    ?days;
  };

  func pow10(n : Nat) : Nat {
    var out : Nat = 1;
    var i : Nat = 0;
    while (i < n) { out *= 10; i += 1 };
    out;
  };

  func padLeft(t : Text, width : Nat) : Text {
    var out = t;
    while (out.size() < width) { out := "0" # out };
    out;
  };

  /// "18.5" -> minor units at `decimals`, exactly. More precision than the
  /// token has is refused rather than rounded: rounding someone's money is
  /// not this canister's call.
  func parseDecimal(t0 : Text, decimals : Nat) : ?Nat {
    var t = Text.trim(t0, #char ' ');
    t := Text.trimStart(t, #char '$');
    let parts = splitParts(t, '.');
    if (parts.size() == 0 or parts.size() > 2) return null;
    let wholeText = if (parts[0] == "") "0" else parts[0];
    let ?whole = digitsToNat(wholeText) else return null;
    var frac : Nat = 0;
    if (parts.size() == 2) {
      let f = parts[1];
      if (f.size() == 0 or f.size() > decimals) return null;
      let ?fv = digitsToNat(f) else return null;
      frac := fv * pow10(decimals - f.size() : Nat);
    };
    ?(whole * pow10(decimals) + frac);
  };

  /// An amount argument as a JSON number or a string. Floats go through a
  /// fixed-point format at the token's precision before parsing, so 18.1
  /// arrives as 18.100000 and not as 18.0999999.
  func readAmount(args : McpTypes.JsonValue, field : Text, decimals : Nat) : { #absent; #ok : Nat; #bad } {
    switch (Result.toOption(Json.getAsNat(args, field))) {
      case (?n) return #ok(n * pow10(decimals));
      case (null) {};
    };
    switch (Result.toOption(Json.getAsFloat(args, field))) {
      case (?f) {
        if (f < 0.0) return #bad;
        // Refuse, rather than round, a float with more precision than the
        // token: printed three digits further, it must end in zeros.
        let atPrecision = Float.format(#fix(Nat8.fromNat(decimals)), f);
        let further = Float.format(#fix(Nat8.fromNat(decimals + 3)), f);
        if (further != atPrecision # (if (decimals == 0) ".000" else "000")) return #bad;
        return switch (parseDecimal(atPrecision, decimals)) {
          case (?n) #ok(n);
          case (null) #bad;
        };
      };
      case (null) {};
    };
    switch (Result.toOption(Json.getAsText(args, field))) {
      case (?t) {
        if (Text.trim(t, #char ' ') == "") return #absent;
        switch (parseDecimal(t, decimals)) { case (?n) #ok(n); case (null) #bad };
      };
      case (null) #absent;
    };
  };

  /// Minor units -> "18.50". Integer math only; at least two decimals shown.
  func fmtNum(minor : Nat, decimals : Nat) : Text {
    if (decimals == 0) return Nat.toText(minor);
    let scale = pow10(decimals);
    var frac = Text.trimEnd(padLeft(Nat.toText(minor % scale), decimals), #char '0');
    let keep = if (decimals < 2) decimals else 2;
    while (frac.size() < keep) { frac := frac # "0" };
    Nat.toText(minor / scale) # (if (frac == "") "" else "." # frac);
  };

  // --- GENERIC HELPERS ---

  func callerPrincipal(auth : ?AuthTypes.AuthInfo) : ?Principal {
    switch (auth) {
      case (?info) ?info.principal;
      case (null) null;
    };
  };

  func optText(args : McpTypes.JsonValue, field : Text) : ?Text {
    switch (Result.toOption(Json.getAsText(args, field))) {
      case (?t) { let v = Text.trim(t, #char ' '); if (v == "") null else ?v };
      case (null) null;
    };
  };

  func optNat(args : McpTypes.JsonValue, field : Text) : ?Nat {
    switch (Result.toOption(Json.getAsNat(args, field))) {
      case (?n) ?n;
      case (null) {
        switch (optText(args, field)) {
          case (?t) digitsToNat(Text.trimStart(t, #char '#'));
          case (null) null;
        };
      };
    };
  };

  func optBool(args : McpTypes.JsonValue, field : Text) : ?Bool {
    switch (Result.toOption(Json.getAsBool(args, field))) {
      case (?b) ?b;
      case (null) {
        switch (optText(args, field)) {
          case (?t) {
            switch (lower(t)) {
              case ("true") ?true;
              case ("yes") ?true;
              case ("false") ?false;
              case ("no") ?false;
              case (_) null;
            };
          };
          case (null) null;
        };
      };
    };
  };

  func errorResult(msg : Text) : McpTypes.CallToolResult {
    { content = [#text({ text = msg })]; isError = true; structuredContent = null };
  };

  func okResult(payload : Json.Json) : McpTypes.CallToolResult {
    {
      content = [#text({ text = Json.stringify(payload, null) })];
      isError = false;
      structuredContent = ?payload;
    };
  };

  func optJsonText(t : ?Text) : Json.Json {
    switch (t) { case (?v) Json.str(v); case (null) Json.nullable() };
  };

  func requireLen(value : Text, field : Text, min : Nat, max : Nat) : ?Text {
    let n = value.size();
    if (n < min) return ?("'" # field # "' must be at least " # Nat.toText(min) # " characters.");
    if (n > max) return ?("'" # field # "' must be at most " # Nat.toText(max) # " characters.");
    null;
  };

  // Shape pre-check before Principal.fromText, which traps on a bad checksum.
  // Principal text is groups of five base32 characters joined by dashes, the
  // last group 1-5 long — so a recipient label like "fresh-market" is never
  // mistaken for one and never reaches the trapping parser.
  func parsePrincipal(t : Text) : ?Principal {
    let trimmed = Text.trim(t, #char ' ');
    let n = trimmed.size();
    if (n < 5 or n > 63) return null;
    for (c in trimmed.chars()) {
      let ok = (Char.isLowercase(c) and Char.isAlphabetic(c)) or Char.isDigit(c) or c == '-';
      if (not ok) return null;
    };
    let groups = splitParts(trimmed, '-');
    if (groups.size() < 2) return null;
    var i = 0;
    while (i < groups.size()) {
      let g = groups[i].size();
      if (i + 1 < groups.size()) { if (g != 5) return null } else { if (g < 1 or g > 5) return null };
      i += 1;
    };
    let p = Principal.fromText(trimmed);
    if (Principal.isAnonymous(p)) return null;
    ?p;
  };

  func shortPrincipal(p : Principal) : Text {
    let parts = splitParts(Principal.toText(p), '-');
    if (parts.size() == 0) Principal.toText(p) else parts[0] # "…";
  };

  func clip(t : Text, n : Nat) : Text {
    if (t.size() <= n) return t;
    let cs = Iter.toArray(t.chars());
    Text.fromIter(Array.subArray(cs, 0, n).vals()) # "…";
  };

  func idsOf<K>(index : Map.Map<K, [Nat]>, hash : Map.HashUtils<K>, k : K) : [Nat] {
    switch (Map.get(index, hash, k)) { case (?ids) ids; case (null) [] };
  };

  func indexAdd<K>(index : Map.Map<K, [Nat]>, hash : Map.HashUtils<K>, k : K, id : Nat) {
    Map.set(index, hash, k, Array.append(idsOf(index, hash, k), [id]));
  };

  // --- HEX ---

  transient let hexChars : [Char] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

  func blobToHex(b : Blob) : Text {
    let buf = Buffer.Buffer<Char>(b.size() * 2);
    for (byte in b.vals()) {
      let n = Nat8.toNat(byte);
      buf.add(hexChars[n / 16]);
      buf.add(hexChars[n % 16]);
    };
    Text.fromIter(buf.vals());
  };

  func hexDigitVal(c : Char) : ?Nat {
    let n = Nat32.toNat(Char.toNat32(c));
    if (n >= 48 and n <= 57) return ?(n - 48 : Nat);
    if (n >= 97 and n <= 102) return ?(n - 87 : Nat);
    null;
  };

  /// 64 hex chars -> a 32-byte subaccount. All zeros means the default
  /// account, which is stored as null so the two spellings compare equal.
  func parseSubaccount(t : Text) : { #none; #ok : ?Blob; #bad } {
    let s = lower(Text.trim(t, #char ' '));
    if (s == "") return #none;
    let cs = Iter.toArray(s.chars());
    if (cs.size() != 64) return #bad;
    let bytes = Array.init<Nat8>(32, 0);
    var zero = true;
    var i = 0;
    while (i < 32) {
      let ?hi = hexDigitVal(cs[2 * i]) else return #bad;
      let ?lo = hexDigitVal(cs[2 * i + 1]) else return #bad;
      let v = hi * 16 + lo;
      if (v != 0) zero := false;
      bytes[i] := Nat8.fromNat(v);
      i += 1;
    };
    if (zero) #ok(null) else #ok(?Blob.fromArray(Array.freeze(bytes)));
  };

  func accountText(a : Account) : Text {
    switch (a.subaccount) {
      case (?s) Principal.toText(a.owner) # " (subaccount " # blobToHex(s) # ")";
      case (null) Principal.toText(a.owner);
    };
  };

  // --- ISSUED AGENTS ---
  //
  // An issued agent's principal is an opaque id (type byte 0x01) derived from
  // this canister, the owner, and the agent id. Opaque ids of this length are
  // never user or canister principals, and nobody holds a private key for
  // one: it exists only as the identity behind the API key minted here.

  func issuedPrincipalFor(owner : Principal, id : Nat) : Principal {
    let seed = "delegation-registry-agent|" # Principal.toText(Principal.fromActor(self)) # "|" # Principal.toText(owner) # "|" # Nat.toText(id);
    let h = Blob.toArray(Sha256.fromBlob(#sha256, Text.encodeUtf8(seed)));
    Principal.fromBlob(Blob.fromArray(Array.tabulate<Nat8>(29, func(i) { if (i < 28) h[i] else 0x01 })));
  };

  func isIssued(p : Principal) : Bool {
    switch (Map.get(issuedPrincipals, phash, p)) { case (?_) true; case (null) false };
  };

  func keyStore() : ?AuthTypes.ApiKeyStore {
    switch (authContext.apiKey) { case (?s) ?s.apiKeys; case (null) null };
  };

  /// Mint an API key bound to `p`, exactly as the SDK's create_my_api_key
  /// does for a caller: random bytes, hex out, sha256-hex stored.
  func mintKeyFor(p : Principal, name : Text) : async* ?(Text, Text) {
    let ?store = keyStore() else return null;
    let raw = await Random.blob();
    let hashed = Base16.encode(Sha256.fromBlob(#sha256, raw));
    Map.set(store, thash, hashed, { principal = p; scopes = []; name = name; created = Time.now() });
    ?(Base16.encode(raw), hashed);
  };

  func dropKey(hash : ?Text) {
    switch (hash, keyStore()) {
      case (?h, ?store) ignore Map.remove(store, thash, h);
      case (_, _) {};
    };
  };

  // --- EVENTS ---

  func logEvent(owner : Principal, agentId : ?Nat, grantId : ?Nat, kind : Text, ok : Bool, detail : Text) {
    let ev : Event = { at = Time.now(); agentId = agentId; grantId = grantId; kind = kind; ok = ok; detail = detail };
    let cur = switch (Map.get(eventsByOwner, phash, owner)) { case (?e) e; case (null) [] };
    let kept = if (cur.size() >= maxEventsPerOwner) {
      Array.subArray(cur, cur.size() + 1 - maxEventsPerOwner, maxEventsPerOwner - 1 : Nat);
    } else cur;
    Map.set(eventsByOwner, phash, owner, Array.append(kept, [ev]));
  };

  // --- GRANT LOGIC ---

  func agentOf(g : Grant) : ?Agent { Map.get(agentsById, nhash, g.agentId) };

  func agentName(id : Nat) : Text {
    switch (Map.get(agentsById, nhash, id)) { case (?a) a.name; case (null) "agent " # Nat.toText(id) };
  };

  func decimalsOf(g : Grant) : Nat {
    switch (g.kind) { case (#spend(s)) Nat8.toNat(s.asset.decimals); case (#action(_)) actionDecimals };
  };

  func unitOf(g : Grant) : Text {
    switch (g.kind) {
      case (#spend(s)) " " # s.asset.symbol;
      case (#action(a)) switch (a.unit) { case (?u) " " # u; case (null) "" };
    };
  };

  func amt(g : Grant, minor : Nat) : Text { fmtNum(minor, decimalsOf(g)) # unitOf(g) };

  func usageNow(g : Grant, now : Int) : Usage {
    let key = periodKey(g.period, now);
    if (g.usage.periodKey == key) g.usage else ({ periodKey = key; amount = 0; uses = 0 });
  };

  func stateText(g : Grant, now : Int) : Text {
    if (g.revokedAt != null) return "revoked";
    if (now >= g.expiresAt) return "expired";
    switch (agentOf(g)) {
      case (?a) {
        switch (a.status) { case (#paused) return "agent paused"; case (#removed) return "agent removed"; case (#active) {} };
      };
      case (null) return "agent removed";
    };
    "active";
  };

  func isLive(g : Grant, now : Int) : Bool { stateText(g, now) == "active" };

  func resetText(g : Grant, now : Int) : ?Text {
    switch (periodEnd(g.period, periodKey(g.period, now))) { case (?t) ?fmtUtc(t); case (null) null };
  };

  /// Why this use is refused, or null if it is allowed. Returns a short code
  /// (safe to show a third party) and the full reason (owner and agent only).
  func refusal(g : Grant, now : Int, amount : ?Nat, counterparty : ?Principal) : ?(Text, Text) {
    let gid = "Grant " # Nat.toText(g.id);
    let st = stateText(g, now);
    if (st != "active") {
      let detail = if (st == "expired") gid # " expired " # fmtUtc(g.expiresAt) # "." else gid # " is " # st # ".";
      return ?(st, detail);
    };
    let u = usageNow(g, now);
    let limitsAmounts = g.perUseMax != null or g.budget != null;
    switch (amount) {
      case (null) {
        if (limitsAmounts) return ?("amount required", gid # " limits amounts, so pass 'amount' for this use.");
      };
      case (?a) {
        switch (g.perUseMax) {
          case (?cap) {
            if (a > cap) return ?("over per-use limit", amt(g, a) # " is over " # gid # "'s limit of " # amt(g, cap) # " per use.");
          };
          case (null) {};
        };
        switch (g.budget) {
          case (?b) {
            if (u.amount + a > b) {
              let left : Nat = if (b > u.amount) b - u.amount else 0;
              let resets = switch (resetText(g, now)) { case (?t) " It resets " # t # "."; case (null) " It does not reset." };
              return ?("over budget", amt(g, a) # " would exceed " # gid # "'s " # amt(g, b) # " budget " # periodPhrase(g.period) # ": " # amt(g, u.amount) # " is used and " # amt(g, left) # " is left." # resets);
            };
          };
          case (null) {};
        };
      };
    };
    switch (g.maxUses) {
      case (?m) {
        if (u.uses + 1 > m) return ?("use limit reached", gid # " allows " # Nat.toText(m) # " uses " # periodPhrase(g.period) # " and all of them are used.");
      };
      case (null) {};
    };
    switch (g.kind) {
      case (#action(a)) {
        if (a.counterparties.size() > 0) {
          switch (counterparty) {
            case (null) return ?("counterparty required", gid # " is limited to named counterparties; pass 'counterparty'.");
            case (?c) {
              if (Array.find<Principal>(a.counterparties, func(x) { x == c }) == null) {
                return ?("counterparty not allowed", gid # " does not cover counterparty " # shortPrincipal(c) # ".");
              };
            };
          };
        };
      };
      case (#spend(_)) {};
    };
    null;
  };

  func putGrant(g : Grant) { Map.set(grantsById, nhash, g.id, g) };

  /// Count one use of `amount` against the grant's current period.
  func recordUse(g : Grant, now : Int, amount : Nat) : Grant {
    let u = usageNow(g, now);
    let g2 = {
      g with usage = { periodKey = u.periodKey; amount = u.amount + amount; uses = u.uses + 1 };
      lifetimeAmount = g.lifetimeAmount + amount;
      lifetimeUses = g.lifetimeUses + 1;
      lastUsedAt = ?now;
    };
    putGrant(g2);
    g2;
  };

  /// Undo a reservation after the ledger refused. If the period rolled over
  /// while the call was in flight, the old period's count is already gone.
  func releaseUse(gid : Nat, periodKeyAtReserve : Int, amount : Nat) {
    let ?g = Map.get(grantsById, nhash, gid) else return;
    let u : Usage = if (g.usage.periodKey == periodKeyAtReserve) ({
      periodKey = g.usage.periodKey;
      amount = if (g.usage.amount >= amount) g.usage.amount - amount else 0;
      uses = if (g.usage.uses >= 1) g.usage.uses - 1 else 0;
    }) else g.usage;
    putGrant({
      g with usage = u;
      lifetimeAmount = if (g.lifetimeAmount >= amount) g.lifetimeAmount - amount else 0;
      lifetimeUses = if (g.lifetimeUses >= 1) g.lifetimeUses - 1 else 0;
    });
  };

  // --- JSON VIEWS ---

  func agentJson(a : Agent, now : Int) : Json.Json {
    var live = 0;
    for (gid in idsOf(grantIdsByAgent, nhash, a.id).vals()) {
      switch (Map.get(grantsById, nhash, gid)) { case (?g) { if (isLive(g, now)) live += 1 }; case (null) {} };
    };
    Json.obj([
      ("id", Json.int(a.id)),
      ("name", Json.str(a.name)),
      ("principal", Json.str(Principal.toText(a.principal))),
      ("kind", Json.str(if (a.issued) "issued" else "linked")),
      ("status", Json.str(switch (a.status) { case (#active) "active"; case (#paused) "paused"; case (#removed) "removed" })),
      ("active_grants", Json.int(live)),
      ("created", Json.str(fmtUtc(a.createdAt))),
    ]);
  };

  func optAmt(g : Grant, v : ?Nat) : Json.Json {
    switch (v) { case (?n) Json.str(amt(g, n)); case (null) Json.nullable() };
  };

  func grantJson(g : Grant, now : Int) : Json.Json {
    let u = usageNow(g, now);
    let base = Buffer.Buffer<(Text, Json.Json)>(24);
    base.add(("id", Json.int(g.id)));
    base.add(("agent", Json.str(agentName(g.agentId) # " (#" # Nat.toText(g.agentId) # ")")));
    base.add(("status", Json.str(stateText(g, now))));
    base.add(("purpose", Json.str(g.purpose)));
    switch (g.kind) {
      case (#spend(s)) {
        base.add(("kind", Json.str("spend")));
        base.add(("token", Json.str(s.asset.symbol)));
        base.add(("ledger", Json.str(s.asset.ledger)));
        base.add(("any_recipient", Json.bool(s.anyRecipient)));
        base.add(("recipients", Json.arr(Array.map<Recipient, Json.Json>(s.recipients, func(r) { Json.obj([("label", Json.str(r.label_)), ("account", Json.str(accountText(r.account)))]) }))));
      };
      case (#action(a)) {
        base.add(("kind", Json.str("action")));
        base.add(("action", Json.str(a.action)));
        base.add(("counterparties", Json.arr(Array.map<Principal, Json.Json>(a.counterparties, func(p) { Json.str(Principal.toText(p)) }))));
      };
    };
    base.add(("per_use_max", optAmt(g, g.perUseMax)));
    base.add(("budget", optAmt(g, g.budget)));
    base.add(("max_uses", switch (g.maxUses) { case (?m) Json.int(m); case (null) Json.nullable() }));
    base.add(("period", Json.str(periodText(g.period))));
    base.add(("used_this_period", Json.str(amt(g, u.amount))));
    base.add(("uses_this_period", Json.int(u.uses)));
    base.add((
      "left_this_period",
      switch (g.budget) { case (?b) Json.str(amt(g, if (b > u.amount) b - u.amount else 0)); case (null) Json.nullable() },
    ));
    base.add(("period_resets", optJsonText(resetText(g, now))));
    base.add(("expires", Json.str(fmtUtc(g.expiresAt))));
    base.add(("lifetime_total", Json.str(amt(g, g.lifetimeAmount))));
    base.add(("lifetime_uses", Json.int(g.lifetimeUses)));
    base.add(("created", Json.str(fmtUtc(g.createdAt))));
    Json.obj(Buffer.toArray(base));
  };

  func paymentStatusText(s : PaymentStatus) : Text {
    switch (s) {
      case (#pending) "pending";
      case (#sent(_)) "sent";
      case (#failed(_)) "failed";
      case (#uncertain(_)) "uncertain";
    };
  };

  func paymentJson(p : Payment, g : Grant) : Json.Json {
    Json.obj([
      ("payment", Json.int(p.id)),
      ("grant", Json.int(p.grantId)),
      ("status", Json.str(paymentStatusText(p.status))),
      ("amount", Json.str(amt(g, p.amount))),
      ("amount_minor", Json.int(p.amount)),
      ("to", Json.str(switch (p.toLabel) { case (?l) l # " — " # accountText(p.to); case (null) accountText(p.to) })),
      ("ledger_block", switch (p.status) { case (#sent(b)) Json.int(b); case (_) Json.nullable() }),
      ("detail", switch (p.status) { case (#failed(w)) Json.str(w); case (#uncertain(w)) Json.str(w); case (_) Json.nullable() }),
      ("note", optJsonText(p.note)),
      ("request_id", optJsonText(p.requestId)),
      ("at", Json.str(fmtUtc(p.at))),
    ]);
  };

  // --- TOOL SCHEMAS ---

  func schemaProp(name : Text, jsonType : Text, description : Text) : (Text, Json.Json) {
    (name, Json.obj([("type", Json.str(jsonType)), ("description", Json.str(description))]));
  };

  func objSchema(props : [(Text, Json.Json)], required : [Text]) : Json.Json {
    Json.obj([
      ("type", Json.str("object")),
      ("properties", Json.obj(props)),
      ("required", Json.arr(Array.map<Text, Json.Json>(required, Json.str))),
    ]);
  };

  func tool(name : Text, title : Text, description : Text, schema : Json.Json) : McpTypes.Tool {
    { name = name; title = ?title; description = ?description; payment = null; inputSchema = schema; outputSchema = null };
  };

  transient let agentProp = schemaProp("agent", "string", "The agent, by id (e.g. 3) or by the name you gave it.");
  transient let periodProp = schemaProp("period", "string", "When limits reset, in UTC: 'day', 'week' (Monday 00:00), 'month', or 'total' (never).");
  transient let expiresDaysProp = schemaProp("expires_in_days", "number", "Days until the grant ends (1-366). Default 30. Every grant expires.");
  transient let expiresOnProp = schemaProp("expires_on", "string", "Or an end date, 'YYYY-MM-DD' — the grant ends at the end of that day, UTC.");

  transient let recipientsProp : (Text, Json.Json) = (
    "recipients",
    Json.obj([
      ("type", Json.str("array")),
      (
        "items",
        objSchema(
          [
            schemaProp("label", "string", "A name the agent pays by, e.g. 'Fresh Market' (unique on this grant)."),
            schemaProp("principal", "string", "The recipient's ICP principal."),
            schemaProp("subaccount", "string", "Optional 64-hex-char subaccount, if they gave you one."),
          ],
          ["label", "principal"],
        ),
      ),
      ("description", Json.str("Who the agent may pay (up to 20). Required unless any_recipient is true.")),
    ]),
  );

  transient let tools : [McpTypes.Tool] = [
    tool(
      "add_agent",
      "Add Agent",
      "Name an agent you will delegate to. With no 'principal', this ISSUES one: the registry creates a principal for the agent and returns an API key for it — shown once. Give your agent THAT key, never your own; everything it can do here is exactly the grants you give it, and nobody can use an issued principal outside this registry. With a 'principal', this LINKS an identity that already exists (an agent with its own dfx identity, or another business's agent) instead. Then call grant_spend or grant_action.",
      objSchema(
        [
          schemaProp("name", "string", "What you call it, e.g. 'Groceries' or 'Office manager' (1-60 chars, unique among your agents)."),
          schemaProp("principal", "string", "Optional: link this existing principal instead of issuing a new one."),
        ],
        ["name"],
      ),
    ),
    tool(
      "list_agents",
      "List Agents",
      "Your agents: id, name, principal, whether issued or linked, status, and how many grants are active.",
      objSchema([schemaProp("include_removed", "boolean", "Also list removed agents. Default false.")], []),
    ),
    tool(
      "set_agent_status",
      "Pause, Resume, or Remove Agent",
      "'pause' stops every grant the agent has at once, until you 'resume'. 'remove' is permanent: every grant is revoked and an issued agent's key stops working. Use pause first if you are not sure — it is the kill switch.",
      objSchema([agentProp, schemaProp("status", "string", "'pause', 'resume', or 'remove'.")], ["agent", "status"]),
    ),
    tool(
      "new_agent_key",
      "New Agent Key",
      "Replace an issued agent's API key — for a leaked key, or a new machine. The old key stops working immediately; the agent keeps its principal and grants. Shown once.",
      objSchema([agentProp], ["agent"]),
    ),
    tool(
      "grant_spend",
      "Grant Spending",
      "Let an agent pay from your ckUSDC — enforced on-chain. The agent can only pay through this registry's 'pay' tool, which refuses anything over the per-payment cap, over the period budget, to anyone not on the recipient list, or after expiry. You also approve one ICRC-2 allowance to this registry (spending_status gives the exact call); that allowance is a second, ledger-enforced ceiling. Fees (0.01 ckUSDC per payment) are paid by you on top of the caps. Grants cannot be edited — revoke and grant again. v1 caps: 1,000 ckUSDC per payment, 10,000 per period.",
      objSchema(
        [
          agentProp,
          schemaProp("purpose", "string", "What it is for, e.g. 'Weekly groceries' (3-200 chars). The agent sees this."),
          schemaProp("per_payment_max", "number", "Largest single payment, in whole tokens, e.g. 20 or 12.5."),
          schemaProp("budget", "number", "Most the agent can pay per period, in whole tokens."),
          periodProp,
          schemaProp("max_payments", "number", "Optional: at most this many payments per period."),
          recipientsProp,
          schemaProp("any_recipient", "boolean", "Allow paying ANY principal. Default false. Only for grants whose caps you would be fine losing entirely."),
          expiresDaysProp,
          expiresOnProp,
          schemaProp("ledger", "string", "ICRC ledger canister id. Default ckUSDC. Only allowlisted ledgers are accepted."),
        ],
        ["agent", "purpose", "per_payment_max", "budget"],
      ),
    ),
    tool(
      "grant_action",
      "Grant an Action",
      "Let an agent do a named thing in some other app — e.g. 'contract.sign', 'booking.accept', 'invoice.send'. This registry cannot stop an agent in another app; what it gives you is a record the agent checks against and logs every use to (use_permission), and an answer any other app or agent can ask for before trusting yours (check_permission). Optional limits: an amount per use, a budget per period, a count per period, named counterparties. Every grant expires.",
      objSchema(
        [
          agentProp,
          schemaProp("action", "string", "The action name, lowercase, e.g. 'contract.sign' (letters, digits, and . _ : -; up to 60)."),
          schemaProp("purpose", "string", "What it is for, e.g. 'Sign renewals with our two regular suppliers' (3-200 chars)."),
          schemaProp("per_use_max", "number", "Optional largest amount per use (2 decimals), e.g. 500."),
          schemaProp("budget", "number", "Optional total amount per period."),
          schemaProp("unit", "string", "Optional unit for those amounts, e.g. 'USD' (display only)."),
          schemaProp("max_uses", "number", "Optional: at most this many uses per period."),
          periodProp,
          ("counterparties", Json.obj([("type", Json.str("array")), ("items", Json.obj([("type", Json.str("string"))])), ("description", Json.str("Optional: principals this may be done with. Empty means anyone."))])),
          expiresDaysProp,
          expiresOnProp,
        ],
        ["agent", "action", "purpose"],
      ),
    ),
    tool(
      "revoke_grant",
      "Revoke Grant",
      "End a grant now. Payments already sent stay sent; nothing new goes through it. Revoked grants stay in list_grants and activity for the record.",
      objSchema([schemaProp("grant", "number", "The grant id.")], ["grant"]),
    ),
    tool(
      "list_grants",
      "List Grants",
      "Your grants with live usage: used and left this period, when the period resets, when the grant expires, lifetime totals.",
      objSchema(
        [
          schemaProp("agent", "string", "Only this agent's grants (id or name)."),
          schemaProp("include_ended", "boolean", "Also list revoked and expired grants. Default false."),
        ],
        [],
      ),
    ),
    tool(
      "spending_status",
      "Spending Status",
      "Read the ledger live: your allowance to this registry, your balance, and what your active spend grants could still pay this period. Returns the exact icrc2_approve arguments to set an allowance that covers your grants — approve only what you would be comfortable with agents spending in total, because the ledger enforces that ceiling even if everything else failed.",
      objSchema([schemaProp("ledger", "string", "ICRC ledger id. Default: every ledger your active grants use, or ckUSDC.")], []),
    ),
    tool(
      "activity",
      "Activity",
      "What your agents did and tried to do, newest first: payments, recorded uses, REFUSALS (an agent attempting something its grant does not cover), and other apps checking an agent's permission.",
      objSchema(
        [
          schemaProp("agent", "string", "Only this agent (id or name)."),
          schemaProp("refusals_only", "boolean", "Only refused or failed attempts."),
          schemaProp("limit", "number", "How many (default 30, max 100)."),
        ],
        [],
      ),
    ),
    tool(
      "my_grants",
      "My Grants (for agents)",
      "For an AGENT: what you are allowed to do, for whom, and how much is left this period. Call this before acting on your user's behalf, and stay inside it — a refused attempt is logged for your owner to see.",
      objSchema([], []),
    ),
    tool(
      "pay",
      "Pay (for agents)",
      "For an AGENT: pay from your owner's account under a spend grant. The registry checks the grant (recipient, per-payment cap, period budget, expiry) and only then moves the money with icrc2_transfer_from. Only pay for what your user asked for. Pass a request_id and retry with the same one if a call times out — it will never pay twice.",
      objSchema(
        [
          schemaProp("grant", "number", "The spend grant id (see my_grants)."),
          schemaProp("to", "string", "A recipient label from the grant (e.g. 'Fresh Market'), or a principal."),
          schemaProp("to_subaccount", "string", "Optional 64-hex-char subaccount, when 'to' is a principal."),
          schemaProp("amount", "number", "In whole tokens, e.g. 18.5."),
          schemaProp("note", "string", "What it is for, e.g. 'Groceries 9/28' (up to 200 chars). Your owner sees it."),
          schemaProp("request_id", "string", "Your own unique id for this payment, e.g. 'groceries-2026-09-28'. Retrying with it is safe."),
        ],
        ["grant", "to", "amount"],
      ),
    ),
    tool(
      "use_permission",
      "Use a Permission (for agents)",
      "For an AGENT: before you do an action your owner delegated (e.g. sign a contract), check it here and record the use. Returns allowed with the grant it counted against, or refused with the reason — if refused, do not do the action; tell your user. Every use and refusal is in your owner's activity log.",
      objSchema(
        [
          schemaProp("action", "string", "The action name, e.g. 'contract.sign'."),
          schemaProp("amount", "number", "The amount involved, if the grant limits amounts."),
          schemaProp("counterparty", "string", "The principal on the other side, if the grant names counterparties."),
          schemaProp("owner", "string", "Which owner, if you are an agent for more than one."),
          schemaProp("grant", "number", "Optional: a specific grant id."),
          schemaProp("note", "string", "What you are doing, e.g. 'Signing contract #12 with Acme' (up to 200 chars)."),
        ],
        ["action"],
      ),
    ),
    tool(
      "check_permission",
      "Check an Agent's Permission",
      "For anyone: before trusting another party's agent, ask whether its owner authorized it to do this. Returns allowed or not, and if allowed the owner, grant, and expiry. It does not reveal budgets. The owner's activity log records that you checked.",
      objSchema(
        [
          schemaProp("agent", "string", "The agent's principal."),
          schemaProp("action", "string", "The action, e.g. 'contract.sign'."),
          schemaProp("amount", "number", "The amount involved, if any."),
          schemaProp("counterparty", "string", "The principal the agent would be dealing with (often yours)."),
          schemaProp("owner", "string", "Optional: only count grants from this owner principal."),
        ],
        ["agent", "action"],
      ),
    ),
  ];

  // --- TOOL IMPLEMENTATIONS ---

  type ToolCb = (Result.Result<McpTypes.CallToolResult, McpTypes.HandlerError>) -> ();

  func fail(cb : ToolCb, msg : Text) { cb(#ok(errorResult(msg))) };

  func requireAuth(auth : ?AuthTypes.AuthInfo, cb : ToolCb) : ?Principal {
    switch (callerPrincipal(auth)) {
      case (?p) ?p;
      case (null) { fail(cb, "Authentication required: call this tool with a valid x-api-key."); null };
    };
  };

  /// Owner tools refuse issued-agent keys: an agent never manages grants.
  func requireOwner(auth : ?AuthTypes.AuthInfo, cb : ToolCb) : ?Principal {
    let ?p = requireAuth(auth, cb) else return null;
    if (isIssued(p)) {
      fail(cb, "This is an agent's key. Agents can use my_grants, pay, use_permission, and check_permission; managing agents and grants takes the owner's own key.");
      return null;
    };
    ?p;
  };

  func ownerAgents(owner : Principal, includeRemoved : Bool) : [Agent] {
    let out = Buffer.Buffer<Agent>(8);
    for (id in idsOf(agentIdsByOwner, phash, owner).vals()) {
      switch (Map.get(agentsById, nhash, id)) {
        case (?a) { if (includeRemoved or a.status != #removed) out.add(a) };
        case (null) {};
      };
    };
    Buffer.toArray(out);
  };

  /// The owner's (non-removed) agent named by 'agent' — an id or a name.
  func findAgent(owner : Principal, args : McpTypes.JsonValue) : Result.Result<Agent, Text> {
    let agents = ownerAgents(owner, false);
    switch (optNat(args, "agent")) {
      case (?id) {
        for (a in agents.vals()) { if (a.id == id) return #ok(a) };
      };
      case (null) {};
    };
    switch (optText(args, "agent")) {
      case (?name) {
        let n = lower(name);
        for (a in agents.vals()) { if (lower(a.name) == n) return #ok(a) };
        #err("No agent '" # clip(name, 60) # "' among yours. list_agents shows them.");
      };
      case (null) {
        switch (optNat(args, "agent")) {
          case (?id) #err("No agent #" # Nat.toText(id) # " among yours. list_agents shows them.");
          case (null) #err("'agent' is required: its id or name.");
        };
      };
    };
  };

  func readExpiry(args : McpTypes.JsonValue, now : Int) : Result.Result<Int, Text> {
    let today = floorDiv(now, nanosPerDay);
    switch (optText(args, "expires_on")) {
      case (?t) {
        let ?d = parseDate(t) else return #err("'expires_on' must be a date as YYYY-MM-DD.");
        let end = (d + 1) * nanosPerDay;
        if (end <= now) return #err("'expires_on' is in the past.");
        if (d - today > maxExpiryDays) return #err("A grant can last at most " # Nat.toText(maxExpiryDays) # " days.");
        return #ok(end);
      };
      case (null) {};
    };
    let days = switch (optNat(args, "expires_in_days")) { case (?n) n; case (null) defaultExpiryDays };
    if (days < 1 or days > maxExpiryDays) return #err("'expires_in_days' must be 1-" # Nat.toText(maxExpiryDays) # ".");
    #ok(now + days * nanosPerDay);
  };

  func readPeriod(args : McpTypes.JsonValue, default_ : Period) : Result.Result<Period, Text> {
    switch (optText(args, "period")) {
      case (null) #ok(default_);
      case (?t) {
        switch (lower(t)) {
          case ("day") #ok(#day);
          case ("daily") #ok(#day);
          case ("week") #ok(#week);
          case ("weekly") #ok(#week);
          case ("month") #ok(#month);
          case ("monthly") #ok(#month);
          case ("total") #ok(#total);
          case ("lifetime") #ok(#total);
          case (_) #err("'period' must be day, week, month, or total.");
        };
      };
    };
  };

  func grantCapProblem(owner : Principal, now : Int) : ?Text {
    let ids = idsOf(grantIdsByOwner, phash, owner);
    if (ids.size() >= maxGrantsPerOwner) return ?("You have made " # Nat.toText(maxGrantsPerOwner) # " grants, the limit per owner.");
    var live = 0;
    for (id in ids.vals()) {
      switch (Map.get(grantsById, nhash, id)) { case (?g) { if (isLive(g, now)) live += 1 }; case (null) {} };
    };
    if (live >= maxActiveGrantsPerOwner) ?("You have " # Nat.toText(maxActiveGrantsPerOwner) # " active grants, the limit. Revoke one first.") else null;
  };

  func newGrant(owner : Principal, agent : Agent, kind : GrantKind, purpose : Text, perUseMax : ?Nat, budget : ?Nat, maxUses : ?Nat, period : Period, expiresAt : Int, now : Int) : Grant {
    let g : Grant = {
      id = nextGrantId;
      owner = owner;
      agentId = agent.id;
      kind = kind;
      purpose = purpose;
      perUseMax = perUseMax;
      budget = budget;
      maxUses = maxUses;
      period = period;
      expiresAt = expiresAt;
      createdAt = now;
      revokedAt = null;
      usage = { periodKey = periodKey(period, now); amount = 0; uses = 0 };
      lifetimeAmount = 0;
      lifetimeUses = 0;
      lastUsedAt = null;
    };
    nextGrantId += 1;
    putGrant(g);
    indexAdd(grantIdsByOwner, phash, owner, g.id);
    indexAdd(grantIdsByAgent, nhash, agent.id, g.id);
    g;
  };

  // --- add_agent ---

  func addAgentTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    let ?name = optText(args, "name") else return fail(cb, "'name' is required, e.g. 'Groceries'.");
    switch (requireLen(name, "name", 1, maxNameChars)) { case (?e) return fail(cb, e); case (null) {} };
    let existing = ownerAgents(owner, false);
    if (existing.size() >= maxAgentsPerOwner) return fail(cb, "You have " # Nat.toText(maxAgentsPerOwner) # " agents, the limit. Remove one first.");
    for (a in existing.vals()) {
      if (lower(a.name) == lower(name)) return fail(cb, "You already have an agent named '" # a.name # "' (#" # Nat.toText(a.id) # ").");
    };
    if (digitsToNat(name) != null) return fail(cb, "Give the agent a name, not a number — numbers are how agents are referred to by id.");

    let linked : ?Principal = switch (optText(args, "principal")) {
      case (null) null;
      case (?t) {
        let ?p = parsePrincipal(t) else return fail(cb, "'" # clip(t, 70) # "' is not a principal.");
        if (p == owner) return fail(cb, "That is your own principal. An agent needs an identity of its own — leave 'principal' out and one is issued.");
        if (p == Principal.fromActor(self)) return fail(cb, "That is this registry's own principal.");
        if (isIssued(p)) return fail(cb, "That principal is an agent issued by this registry to someone else; it cannot be linked.");
        for (a in existing.vals()) {
          if (a.principal == p) return fail(cb, "That principal is already your agent '" # a.name # "' (#" # Nat.toText(a.id) # ").");
        };
        ?p;
      };
    };

    let id = nextAgentId;
    nextAgentId += 1;

    switch (linked) {
      case (?p) {
        let a : Agent = { id = id; owner = owner; name = name; principal = p; issued = false; keyHash = null; status = #active; createdAt = now };
        Map.set(agentsById, nhash, id, a);
        indexAdd(agentIdsByOwner, phash, owner, id);
        indexAdd(agentIdsByPrincipal, phash, p, id);
        logEvent(owner, ?id, null, "agent_added", true, "Linked " # Principal.toText(p) # " as '" # name # "'.");
        cb(#ok(okResult(Json.obj([
          ("message", Json.str("Linked '" # name # "' as agent #" # Nat.toText(id) # ". It uses its own key; grants you give it apply to that principal. Next: grant_spend or grant_action.")),
          ("agent", agentJson(a, now)),
        ]))));
      };
      case (null) {
        let p = issuedPrincipalFor(owner, id);
        // Record the agent before the await, so a racing call sees the name taken.
        let a0 : Agent = { id = id; owner = owner; name = name; principal = p; issued = true; keyHash = null; status = #active; createdAt = now };
        Map.set(agentsById, nhash, id, a0);
        indexAdd(agentIdsByOwner, phash, owner, id);
        indexAdd(agentIdsByPrincipal, phash, p, id);
        Map.set(issuedPrincipals, phash, p, id);
        let minted = try { await* mintKeyFor(p, "agent " # Nat.toText(id) # ": " # name) } catch (e) {
          Map.set(agentsById, nhash, id, { a0 with status = #removed });
          return fail(cb, "Could not generate a key: " # Error.message(e) # ". Try again.");
        };
        let ?(rawKey, hashed) = minted else return fail(cb, "API keys are not enabled on this canister.");
        let ?a1 = Map.get(agentsById, nhash, id) else return;
        if (a1.status == #removed) { dropKey(?hashed); return fail(cb, "The agent was removed while its key was being made.") };
        let a = { a1 with keyHash = ?hashed };
        Map.set(agentsById, nhash, id, a);
        logEvent(owner, ?id, null, "agent_added", true, "Issued agent '" # name # "' (" # shortPrincipal(p) # ").");
        cb(#ok(okResult(Json.obj([
          ("message", Json.str("Issued agent '" # name # "' (#" # Nat.toText(id) # "). Its API key is below and is shown ONLY now — give it to the agent as its x-api-key for this server, instead of yours. With it the agent can do only what you grant. Next: grant_spend or grant_action.")),
          ("api_key", Json.str(rawKey)),
          ("agent", agentJson(a, now)),
        ]))));
      };
    };
  };

  // --- list_agents ---

  func listAgentsTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    let include = switch (optBool(args, "include_removed")) { case (?b) b; case (null) false };
    let agents = ownerAgents(owner, include);
    cb(#ok(okResult(Json.obj([
      ("count", Json.int(agents.size())),
      ("agents", Json.arr(Array.map<Agent, Json.Json>(agents, func(a) { agentJson(a, now) }))),
      ("hint", Json.str(if (agents.size() == 0) "No agents yet. add_agent issues one." else "grant_spend / grant_action give an agent something to do.")),
    ]))));
  };

  // --- set_agent_status ---

  func setAgentStatusTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    let a = switch (findAgent(owner, args)) { case (#ok(a)) a; case (#err(e)) return fail(cb, e) };
    let ?s = optText(args, "status") else return fail(cb, "'status' is required: pause, resume, or remove.");
    switch (lower(s)) {
      case ("pause") {
        if (a.status == #paused) return fail(cb, "'" # a.name # "' is already paused.");
        Map.set(agentsById, nhash, a.id, { a with status = #paused });
        logEvent(owner, ?a.id, null, "agent_paused", true, "Paused '" # a.name # "'. Every grant is suspended.");
        cb(#ok(okResult(Json.obj([("message", Json.str("Paused '" # a.name # "'. Every grant it holds refuses until you resume it.")), ("agent", agentJson({ a with status = #paused }, now))]))));
      };
      case ("resume") {
        if (a.status == #active) return fail(cb, "'" # a.name # "' is not paused.");
        Map.set(agentsById, nhash, a.id, { a with status = #active });
        logEvent(owner, ?a.id, null, "agent_resumed", true, "Resumed '" # a.name # "'.");
        cb(#ok(okResult(Json.obj([("message", Json.str("Resumed '" # a.name # "'. Its unexpired, unrevoked grants work again.")), ("agent", agentJson({ a with status = #active }, now))]))));
      };
      case ("remove") {
        var revoked = 0;
        for (gid in idsOf(grantIdsByAgent, nhash, a.id).vals()) {
          switch (Map.get(grantsById, nhash, gid)) {
            case (?g) { if (g.revokedAt == null) { putGrant({ g with revokedAt = ?now }); revoked += 1 } };
            case (null) {};
          };
        };
        dropKey(a.keyHash);
        let removed = { a with status = #removed; keyHash = null };
        Map.set(agentsById, nhash, a.id, removed);
        logEvent(owner, ?a.id, null, "agent_removed", true, "Removed '" # a.name # "'; revoked " # Nat.toText(revoked) # " grant(s)" # (if (a.issued) " and deleted its key." else "."));
        cb(#ok(okResult(Json.obj([
          ("message", Json.str("Removed '" # a.name # "'. " # Nat.toText(revoked) # " grant(s) revoked" # (if (a.issued) "; its key no longer works." else "."))),
          ("agent", agentJson(removed, now)),
        ]))));
      };
      case (_) fail(cb, "'status' must be pause, resume, or remove.");
    };
  };

  // --- new_agent_key ---

  func newAgentKeyTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    let a = switch (findAgent(owner, args)) { case (#ok(a)) a; case (#err(e)) return fail(cb, e) };
    if (not a.issued) return fail(cb, "'" # a.name # "' is a linked principal with its own keys; only issued agents get keys from this registry.");
    let minted = try { await* mintKeyFor(a.principal, "agent " # Nat.toText(a.id) # ": " # a.name) } catch (e) {
      return fail(cb, "Could not generate a key: " # Error.message(e) # ". The old key still works.");
    };
    let ?(rawKey, hashed) = minted else return fail(cb, "API keys are not enabled on this canister.");
    let ?cur = Map.get(agentsById, nhash, a.id) else return;
    if (cur.status == #removed) { dropKey(?hashed); return fail(cb, "The agent was removed meanwhile.") };
    dropKey(cur.keyHash);
    let updated = { cur with keyHash = ?hashed };
    Map.set(agentsById, nhash, a.id, updated);
    logEvent(owner, ?a.id, null, "key_replaced", true, "New key for '" # a.name # "'; the old one stopped working.");
    cb(#ok(okResult(Json.obj([
      ("message", Json.str("New key for '" # a.name # "' — shown only now. The old key stopped working.")),
      ("api_key", Json.str(rawKey)),
      ("agent", agentJson(updated, now)),
    ]))));
  };

  // --- grant_spend ---

  func grantSpendTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    let agent = switch (findAgent(owner, args)) { case (#ok(a)) a; case (#err(e)) return fail(cb, e) };
    switch (grantCapProblem(owner, now)) { case (?e) return fail(cb, e); case (null) {} };
    let ?purpose = optText(args, "purpose") else return fail(cb, "'purpose' is required, e.g. 'Weekly groceries'.");
    switch (requireLen(purpose, "purpose", 3, maxPurposeChars)) { case (?e) return fail(cb, e); case (null) {} };

    let ledger = switch (optText(args, "ledger")) { case (?l) l; case (null) ckusdcLedger };
    let ?allowed = Map.get(allowedAssets, thash, ledger) else return fail(cb, "Ledger " # clip(ledger, 70) # " is not on the allowlist. v1 accepts ckUSDC (" # ckusdcLedger # ").");
    let asset : Asset = { ledger = ledger; symbol = allowed.symbol; decimals = allowed.decimals };
    let d = Nat8.toNat(asset.decimals);

    let perUse = switch (readAmount(args, "per_payment_max", d)) {
      case (#ok(n)) n;
      case (#absent) return fail(cb, "'per_payment_max' is required: the largest single payment, e.g. 20.");
      case (#bad) return fail(cb, "'per_payment_max' must be a positive amount with at most " # Nat.toText(d) # " decimals.");
    };
    let budget = switch (readAmount(args, "budget", d)) {
      case (#ok(n)) n;
      case (#absent) return fail(cb, "'budget' is required: the most the agent can pay per period, e.g. 50.");
      case (#bad) return fail(cb, "'budget' must be a positive amount with at most " # Nat.toText(d) # " decimals.");
    };
    if (perUse == 0 or budget == 0) return fail(cb, "Caps must be greater than zero.");
    if (perUse > budget) return fail(cb, "'per_payment_max' is larger than 'budget'; a single payment could never use it.");
    if (perUse > allowed.capMinor) return fail(cb, "v1 caps a single payment at " # fmtNum(allowed.capMinor, d) # " " # asset.symbol # ".");
    if (budget > allowed.capMinor * budgetCapMultiple) return fail(cb, "v1 caps a period budget at " # fmtNum(allowed.capMinor * budgetCapMultiple, d) # " " # asset.symbol # ".");
    let period = switch (readPeriod(args, #week)) { case (#ok(p)) p; case (#err(e)) return fail(cb, e) };
    let maxUses = optNat(args, "max_payments");
    switch (maxUses) { case (?0) return fail(cb, "'max_payments' must be at least 1."); case (_) {} };
    let expiresAt = switch (readExpiry(args, now)) { case (#ok(t)) t; case (#err(e)) return fail(cb, e) };

    let anyRecipient = switch (optBool(args, "any_recipient")) { case (?b) b; case (null) false };
    let recips = Buffer.Buffer<Recipient>(4);
    switch (Result.toOption(Json.getAsArray(args, "recipients"))) {
      case (?items) {
        for (item in items.vals()) {
          let ?label_ = optText(item, "label") else return fail(cb, "Each recipient needs a 'label', e.g. 'Fresh Market'.");
          switch (requireLen(label_, "label", 1, maxLabelChars)) { case (?e) return fail(cb, e); case (null) {} };
          let ?pt = optText(item, "principal") else return fail(cb, "Recipient '" # label_ # "' needs a 'principal'.");
          let ?pr = parsePrincipal(pt) else return fail(cb, "Recipient '" # label_ # "': '" # clip(pt, 70) # "' is not a principal.");
          let sub = switch (optText(item, "subaccount")) {
            case (null) null;
            case (?st) switch (parseSubaccount(st)) {
              case (#ok(s)) s;
              case (#none) null;
              case (#bad) return fail(cb, "Recipient '" # label_ # "': 'subaccount' must be 64 hex characters.");
            };
          };
          let acct : Account = { owner = pr; subaccount = sub };
          switch (unspendable(owner, acct)) { case (?why) return fail(cb, "Recipient '" # label_ # "': " # why); case (null) {} };
          for (r in recips.vals()) {
            if (lower(r.label_) == lower(label_)) return fail(cb, "The label '" # label_ # "' is used twice.");
            if (r.account == acct) return fail(cb, "'" # label_ # "' and '" # r.label_ # "' are the same account.");
          };
          recips.add({ label_ = label_; account = acct });
        };
      };
      case (null) {};
    };
    if (recips.size() > maxRecipients) return fail(cb, "At most " # Nat.toText(maxRecipients) # " recipients per grant.");
    if (recips.size() == 0 and not anyRecipient) return fail(cb, "Name who the agent may pay in 'recipients' — or, only if you mean it, set any_recipient to true.");

    let g = newGrant(owner, agent, #spend({ asset = asset; recipients = Buffer.toArray(recips); anyRecipient = anyRecipient }), purpose, ?perUse, ?budget, maxUses, period, expiresAt, now);
    logEvent(owner, ?agent.id, ?g.id, "grant_created", true, "Spend grant #" # Nat.toText(g.id) # " to '" # agent.name # "': up to " # amt(g, perUse) # " per payment, " # amt(g, budget) # " per " # periodText(period) # ", until " # fmtUtc(expiresAt) # ".");
    cb(#ok(okResult(Json.obj([
      ("message", Json.str("Spend grant #" # Nat.toText(g.id) # " is live for '" # agent.name # "'. It pays only once you approve an allowance to this registry on the " # asset.symbol # " ledger — spending_status gives the exact call. Tell the agent to use grant " # Nat.toText(g.id) # ".")),
      ("grant", grantJson(g, now)),
    ]))));
  };

  /// Destinations money must never go to.
  func unspendable(owner : Principal, a : Account) : ?Text {
    if (isIssued(a.owner)) return ?"that is an issued agent principal — nobody could ever move money out of it.";
    if (a.owner == Principal.fromActor(self)) return ?"that is this registry; it holds no funds and could not return them.";
    if (Principal.isAnonymous(a.owner)) return ?"that is the anonymous principal.";
    if (a.owner == owner and a.subaccount == null) return ?"that is your own account — paying yourself only costs a fee.";
    null;
  };

  // --- grant_action ---

  func validAction(t : Text) : ?Text {
    let a = lower(Text.trim(t, #char ' '));
    if (a.size() == 0 or a.size() > maxActionChars) return null;
    for (c in a.chars()) {
      let ok = (Char.isLowercase(c) and Char.isAlphabetic(c)) or Char.isDigit(c) or c == '.' or c == '_' or c == ':' or c == '-';
      if (not ok) return null;
    };
    ?a;
  };

  func grantActionTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    let agent = switch (findAgent(owner, args)) { case (#ok(a)) a; case (#err(e)) return fail(cb, e) };
    switch (grantCapProblem(owner, now)) { case (?e) return fail(cb, e); case (null) {} };
    let ?rawAction = optText(args, "action") else return fail(cb, "'action' is required, e.g. 'contract.sign'.");
    let ?action = validAction(rawAction) else return fail(cb, "'action' may use letters, digits, and . _ : - (up to 60), e.g. 'contract.sign'.");
    let ?purpose = optText(args, "purpose") else return fail(cb, "'purpose' is required.");
    switch (requireLen(purpose, "purpose", 3, maxPurposeChars)) { case (?e) return fail(cb, e); case (null) {} };
    let perUse = switch (readAmount(args, "per_use_max", actionDecimals)) {
      case (#ok(n)) ?n;
      case (#absent) null;
      case (#bad) return fail(cb, "'per_use_max' must be a positive amount with at most 2 decimals.");
    };
    let budget = switch (readAmount(args, "budget", actionDecimals)) {
      case (#ok(n)) ?n;
      case (#absent) null;
      case (#bad) return fail(cb, "'budget' must be a positive amount with at most 2 decimals.");
    };
    switch (perUse, budget) {
      case (?p, ?b) { if (p > b) return fail(cb, "'per_use_max' is larger than 'budget'.") };
      case (_, _) {};
    };
    let unit = optText(args, "unit");
    switch (unit) { case (?u) { switch (requireLen(u, "unit", 1, maxUnitChars)) { case (?e) return fail(cb, e); case (null) {} } }; case (null) {} };
    let maxUses = optNat(args, "max_uses");
    switch (maxUses) { case (?0) return fail(cb, "'max_uses' must be at least 1."); case (_) {} };
    let period = switch (readPeriod(args, #month)) { case (#ok(p)) p; case (#err(e)) return fail(cb, e) };
    let expiresAt = switch (readExpiry(args, now)) { case (#ok(t)) t; case (#err(e)) return fail(cb, e) };
    let cps = Buffer.Buffer<Principal>(4);
    switch (Result.toOption(Json.getAsArray(args, "counterparties"))) {
      case (?items) {
        for (item in items.vals()) {
          let t = switch (item) { case (#string(s)) s; case (_) return fail(cb, "'counterparties' is a list of principal strings.") };
          let ?p = parsePrincipal(t) else return fail(cb, "Counterparty '" # clip(t, 70) # "' is not a principal.");
          if (Buffer.contains<Principal>(cps, p, Principal.equal)) return fail(cb, "Counterparty " # shortPrincipal(p) # " is listed twice.");
          cps.add(p);
        };
      };
      case (null) {};
    };
    if (cps.size() > maxCounterparties) return fail(cb, "At most " # Nat.toText(maxCounterparties) # " counterparties per grant.");

    let g = newGrant(owner, agent, #action({ action = action; unit = unit; counterparties = Buffer.toArray(cps) }), purpose, perUse, budget, maxUses, period, expiresAt, now);
    logEvent(owner, ?agent.id, ?g.id, "grant_created", true, "Action grant #" # Nat.toText(g.id) # " to '" # agent.name # "': " # action # ", until " # fmtUtc(expiresAt) # ".");
    cb(#ok(okResult(Json.obj([
      ("message", Json.str("Action grant #" # Nat.toText(g.id) # " is live: '" # agent.name # "' may '" # action # "'. The agent records each use with use_permission; anyone can confirm it with check_permission using the agent's principal " # Principal.toText(agent.principal) # ".")),
      ("grant", grantJson(g, now)),
    ]))));
  };

  // --- revoke_grant ---

  func revokeGrantTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    let ?gid = optNat(args, "grant") else return fail(cb, "'grant' is required: the grant id.");
    let ?g = Map.get(grantsById, nhash, gid) else return fail(cb, "No grant #" # Nat.toText(gid) # " among yours.");
    if (g.owner != owner) return fail(cb, "No grant #" # Nat.toText(gid) # " among yours.");
    if (g.revokedAt != null) return fail(cb, "Grant #" # Nat.toText(gid) # " is already revoked.");
    let g2 = { g with revokedAt = ?now };
    putGrant(g2);
    logEvent(owner, ?g.agentId, ?gid, "grant_revoked", true, "Revoked grant #" # Nat.toText(gid) # " (" # g.purpose # ").");
    cb(#ok(okResult(Json.obj([("message", Json.str("Revoked grant #" # Nat.toText(gid) # ". Nothing new goes through it.")), ("grant", grantJson(g2, now))]))));
  };

  // --- list_grants ---

  func listGrantsTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    let agentFilter : ?Nat = switch (optText(args, "agent")) {
      case (null) null;
      case (?_) switch (findAgent(owner, args)) { case (#ok(a)) ?a.id; case (#err(e)) return fail(cb, e) };
    };
    let includeEnded = switch (optBool(args, "include_ended")) { case (?b) b; case (null) false };
    let ids = idsOf(grantIdsByOwner, phash, owner);
    let out = Buffer.Buffer<Json.Json>(16);
    var i = ids.size();
    while (i > 0 and out.size() < 50) {
      i -= 1;
      switch (Map.get(grantsById, nhash, ids[i])) {
        case (?g) {
          let agentOk = switch (agentFilter) { case (?a) g.agentId == a; case (null) true };
          let st = stateText(g, now);
          let ended = st == "revoked" or st == "expired" or st == "agent removed";
          if (agentOk and (includeEnded or not ended)) out.add(grantJson(g, now));
        };
        case (null) {};
      };
    };
    cb(#ok(okResult(Json.obj([("count", Json.int(out.size())), ("grants", Json.arr(Buffer.toArray(out)))]))));
  };

  // --- spending_status ---

  func spendingStatusTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let now = Time.now();
    // Group active spend grants by ledger.
    let ledgers = Buffer.Buffer<Text>(2);
    let only = optText(args, "ledger");
    switch (only) { case (?l) ledgers.add(l); case (null) {} };
    let live = Buffer.Buffer<Grant>(8);
    for (gid in idsOf(grantIdsByOwner, phash, owner).vals()) {
      switch (Map.get(grantsById, nhash, gid)) {
        case (?g) {
          switch (g.kind) {
            case (#spend(s)) {
              if (isLive(g, now)) {
                live.add(g);
                if (only == null and not Buffer.contains<Text>(ledgers, s.asset.ledger, Text.equal)) ledgers.add(s.asset.ledger);
              };
            };
            case (#action(_)) {};
          };
        };
        case (null) {};
      };
    };
    if (ledgers.size() == 0) ledgers.add(ckusdcLedger);

    let reports = Buffer.Buffer<Json.Json>(2);
    for (ledger in ledgers.vals()) {
      let ?allowed = Map.get(allowedAssets, thash, ledger) else return fail(cb, "Ledger " # clip(ledger, 70) # " is not on the allowlist.");
      let d = Nat8.toNat(allowed.decimals);
      var leftNow : Nat = 0;
      var fullBudgets : Nat = 0;
      var latestExpiry : Int = now;
      var payments : Nat = 0;
      let rows = Buffer.Buffer<Json.Json>(4);
      for (g in live.vals()) {
        switch (g.kind) {
          case (#spend(s)) {
            if (s.asset.ledger == ledger) {
              let u = usageNow(g, now);
              let b = switch (g.budget) { case (?b) b; case (null) 0 };
              let left : Nat = if (b > u.amount) b - u.amount else 0;
              leftNow += left;
              fullBudgets += b;
              if (g.expiresAt > latestExpiry) latestExpiry := g.expiresAt;
              // Each payment also draws the fee from the allowance. Estimate
              // the count from max_payments, else from budget / per-payment cap.
              payments += switch (g.maxUses, g.perUseMax) {
                case (?m, _) m;
                case (null, ?p) { if (p == 0) 1 else (b + p - 1) / p * 2 };
                case (null, null) 10;
              };
              rows.add(Json.obj([("grant", Json.int(g.id)), ("agent", Json.str(agentName(g.agentId))), ("budget", Json.str(amt(g, b) # " per " # periodText(g.period))), ("left_this_period", Json.str(amt(g, left)))]));
            };
          };
          case (#action(_)) {};
        };
      };
      let l = ledgerOf(ledger);
      let acct : Account = { owner = owner; subaccount = null };
      let spender : Account = { owner = Principal.fromActor(self); subaccount = null };
      let (allowanceJ, balanceJ, feeMinor, allowanceMinor) = try {
        let al = await l.icrc2_allowance({ account = acct; spender = spender });
        let bal = await l.icrc1_balance_of(acct);
        let fee = await l.icrc1_fee();
        let exp = switch (al.expires_at) { case (?e) " (expires " # fmtUtc(Nat64.toNat(e)) # ")"; case (null) "" };
        (Json.str(fmtNum(al.allowance, d) # " " # allowed.symbol # exp), Json.str(fmtNum(bal, d) # " " # allowed.symbol), fee, al.allowance);
      } catch (e) {
        (Json.str("could not read: " # Error.message(e)), Json.nullable(), 0, 0);
      };
      let suggested = fullBudgets + feeMinor * payments;
      let advice = if (live.size() == 0) {
        "No active spend grants. Nothing needs an allowance yet.";
      } else if (allowanceMinor < leftNow) {
        "Your allowance (" # fmtNum(allowanceMinor, d) # ") is below what your grants could still pay this period (" # fmtNum(leftNow, d) # "). Agents will be refused once it runs out — which is safe, but may not be what you want.";
      } else {
        "Your allowance covers what your grants can pay this period. It is also your hard ceiling: the ledger will not let this registry move more, whatever happens here.";
      };
      reports.add(Json.obj([
        ("token", Json.str(allowed.symbol)),
        ("ledger", Json.str(ledger)),
        ("allowance_to_registry", allowanceJ),
        ("balance", balanceJ),
        ("grants_left_this_period", Json.str(fmtNum(leftNow, d) # " " # allowed.symbol)),
        ("grants", Json.arr(Buffer.toArray(rows))),
        ("advice", Json.str(advice)),
        (
          "approve_args",
          Json.obj([
            ("spender", Json.obj([("owner", Json.str(Principal.toText(Principal.fromActor(self))))])),
            ("amount", Json.int(suggested)),
            ("amount_display", Json.str(fmtNum(suggested, d) # " " # allowed.symbol # " = one full period of every active grant, plus estimated fees")),
            ("expires_at", Json.int(latestExpiry)),
          ]),
        ),
        (
          "dfx_example",
          Json.str("dfx canister --network ic call " # ledger # " icrc2_approve '(record { spender = record { owner = principal \"" # Principal.toText(Principal.fromActor(self)) # "\" }; amount = " # Nat.toText(suggested) # " : nat; expires_at = opt (" # Int.toText(latestExpiry) # " : nat64) })'"),
        ),
      ]));
    };
    cb(#ok(okResult(Json.obj([
      ("message", Json.str("An approve REPLACES the previous allowance; it does not add to it. Approving 0 stops all agent spending at the ledger immediately.")),
      ("ledgers", Json.arr(Buffer.toArray(reports))),
    ]))));
  };

  // --- activity ---

  func activityTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?owner = requireOwner(auth, cb) else return;
    let agentFilter : ?Nat = switch (optText(args, "agent")) {
      case (null) null;
      case (?_) switch (findAgent(owner, args)) { case (#ok(a)) ?a.id; case (#err(e)) return fail(cb, e) };
    };
    let refusalsOnly = switch (optBool(args, "refusals_only")) { case (?b) b; case (null) false };
    let limit = switch (optNat(args, "limit")) { case (?n) Nat.min(Nat.max(n, 1), 100); case (null) 30 };
    let events = switch (Map.get(eventsByOwner, phash, owner)) { case (?e) e; case (null) [] };
    let out = Buffer.Buffer<Json.Json>(limit);
    var i = events.size();
    while (i > 0 and out.size() < limit) {
      i -= 1;
      let ev = events[i];
      let agentOk = switch (agentFilter) { case (?a) ev.agentId == ?a; case (null) true };
      if (agentOk and (not refusalsOnly or not ev.ok)) {
        out.add(Json.obj([
          ("at", Json.str(fmtUtc(ev.at))),
          ("event", Json.str(ev.kind)),
          ("ok", Json.bool(ev.ok)),
          ("agent", switch (ev.agentId) { case (?a) Json.str(agentName(a) # " (#" # Nat.toText(a) # ")"); case (null) Json.nullable() }),
          ("grant", switch (ev.grantId) { case (?g) Json.int(g); case (null) Json.nullable() }),
          ("detail", Json.str(ev.detail)),
        ]));
      };
    };
    cb(#ok(okResult(Json.obj([("count", Json.int(out.size())), ("events", Json.arr(Buffer.toArray(out)))]))));
  };

  // --- AGENT SIDE ---

  /// Every agent record behind this principal that is not removed.
  func agentRecordsFor(p : Principal) : [Agent] {
    let out = Buffer.Buffer<Agent>(2);
    for (id in idsOf(agentIdsByPrincipal, phash, p).vals()) {
      switch (Map.get(agentsById, nhash, id)) {
        case (?a) { if (a.status != #removed) out.add(a) };
        case (null) {};
      };
    };
    Buffer.toArray(out);
  };

  // --- my_grants ---

  func myGrantsTool(_args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?p = requireAuth(auth, cb) else return;
    let now = Time.now();
    let records = agentRecordsFor(p);
    if (records.size() == 0) {
      return cb(#ok(okResult(Json.obj([
        ("message", Json.str("This key is nobody's agent here, so it holds no grants. An owner makes you one with add_agent — either issuing you a key or linking your principal " # Principal.toText(p) # ".")),
        ("as", Json.arr([])),
      ]))));
    };
    let blocks = Buffer.Buffer<Json.Json>(records.size());
    for (a in records.vals()) {
      let gs = Buffer.Buffer<Json.Json>(4);
      for (gid in idsOf(grantIdsByAgent, nhash, a.id).vals()) {
        switch (Map.get(grantsById, nhash, gid)) {
          case (?g) { if (g.revokedAt == null and now < g.expiresAt) gs.add(grantJson(g, now)) };
          case (null) {};
        };
      };
      blocks.add(Json.obj([
        ("owner", Json.str(Principal.toText(a.owner))),
        ("agent_name", Json.str(a.name)),
        ("status", Json.str(switch (a.status) { case (#paused) "PAUSED by your owner — every grant refuses until resumed"; case (_) "active" })),
        ("grants", Json.arr(Buffer.toArray(gs))),
      ]));
    };
    cb(#ok(okResult(Json.obj([
      ("message", Json.str("Stay inside these. Spend grants: use 'pay'. Action grants: call use_permission before acting.")),
      ("your_principal", Json.str(Principal.toText(p))),
      ("as", Json.arr(Buffer.toArray(blocks))),
    ]))));
  };

  // --- pay ---

  func payTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?p = requireAuth(auth, cb) else return;
    let now = Time.now();
    let ?gid = optNat(args, "grant") else return fail(cb, "'grant' is required: your spend grant id (see my_grants).");
    let notYours = "No grant #" # Nat.toText(gid) # " among yours. my_grants lists what you hold.";
    let ?g = Map.get(grantsById, nhash, gid) else return fail(cb, notYours);
    let ?agent = agentOf(g) else return fail(cb, notYours);
    if (agent.principal != p) return fail(cb, notYours);
    let #spend(sp) = g.kind else return fail(cb, "Grant #" # Nat.toText(gid) # " is an action grant, not a spend grant; use use_permission.");
    let d = Nat8.toNat(sp.asset.decimals);

    // Retries: the same request_id on the same grant returns the first result.
    let requestId = optText(args, "request_id");
    switch (requestId) {
      case (?r) {
        switch (requireLen(r, "request_id", 1, maxRequestIdChars)) { case (?e) return fail(cb, e); case (null) {} };
        switch (Map.get(paymentByRequest, thash, Nat.toText(gid) # ":" # r)) {
          case (?pid) {
            let ?prev = Map.get(paymentsById, nhash, pid) else return fail(cb, "Payment record missing.");
            let msg = switch (prev.status) {
              case (#pending) "This request_id is already being paid — wait for it; nothing new was sent.";
              case (#sent(_)) "Already paid under this request_id — nothing new was sent.";
              case (#failed(_)) "This request_id already failed (see detail). Use a new request_id to try again.";
              case (#uncertain(_)) "This request_id is uncertain (see detail) — check with your owner before trying again.";
            };
            return cb(#ok(okResult(Json.obj([("message", Json.str(msg)), ("payment", paymentJson(prev, g))]))));
          };
          case (null) {};
        };
      };
      case (null) {};
    };

    let amount = switch (readAmount(args, "amount", d)) {
      case (#ok(0)) return fail(cb, "'amount' must be greater than zero.");
      case (#ok(n)) n;
      case (#absent) return fail(cb, "'amount' is required, in whole tokens, e.g. 18.5.");
      case (#bad) return fail(cb, "'amount' must be a positive number with at most " # Nat.toText(d) # " decimals.");
    };
    let note = optText(args, "note");
    switch (note) { case (?n) { switch (requireLen(n, "note", 1, maxNoteChars)) { case (?e) return fail(cb, e); case (null) {} } }; case (null) {} };

    // Resolve the recipient: a label on the grant, a listed principal, or —
    // only with any_recipient — any principal.
    let ?toText = optText(args, "to") else return fail(cb, "'to' is required: a recipient label from the grant, or a principal.");
    let subArg = switch (optText(args, "to_subaccount")) {
      case (null) null;
      case (?st) switch (parseSubaccount(st)) {
        case (#ok(s)) s;
        case (#none) null;
        case (#bad) return fail(cb, "'to_subaccount' must be 64 hex characters.");
      };
    };
    var resolved : ?(Account, ?Text) = null;
    for (r in sp.recipients.vals()) {
      if (resolved == null and lower(r.label_) == lower(toText)) resolved := ?(r.account, ?r.label_);
    };
    if (resolved == null) {
      switch (parsePrincipal(toText)) {
        case (?pr) {
          let acct : Account = { owner = pr; subaccount = subArg };
          for (r in sp.recipients.vals()) {
            if (resolved == null and r.account == acct) resolved := ?(acct, ?r.label_);
          };
          if (resolved == null and sp.anyRecipient) resolved := ?(acct, null);
        };
        case (null) {};
      };
    };
    let labels = Array.map<Recipient, Text>(sp.recipients, func(r) { r.label_ });
    let ?(to, toLabel) = resolved else {
      let why = "'" # clip(toText, 70) # "' is not a recipient on grant #" # Nat.toText(gid) # (if (labels.size() > 0) ". It may pay: " # Text.join(", ", labels.vals()) # "." else ".");
      logEvent(g.owner, ?agent.id, ?gid, "pay_refused", false, why);
      return fail(cb, why # " Nothing was paid.");
    };
    switch (unspendable(g.owner, to)) {
      case (?why) {
        logEvent(g.owner, ?agent.id, ?gid, "pay_refused", false, "Refused paying " # accountText(to) # ": " # why);
        return fail(cb, "Refused: " # why # " Nothing was paid.");
      };
      case (null) {};
    };

    switch (refusal(g, now, ?amount, null)) {
      case (?(_, why)) {
        logEvent(g.owner, ?agent.id, ?gid, "pay_refused", false, "Refused " # amt(g, amount) # " to " # (switch (toLabel) { case (?l) l; case (null) shortPrincipal(to.owner) }) # ": " # why);
        return fail(cb, why # " Nothing was paid.");
      };
      case (null) {};
    };

    // Invariant 2: reserve against the budget BEFORE the await.
    let reserved = recordUse(g, now, amount);
    let pid = nextPaymentId;
    nextPaymentId += 1;
    let pending : Payment = {
      id = pid;
      grantId = gid;
      owner = g.owner;
      agentId = agent.id;
      to = to;
      toLabel = toLabel;
      amount = amount;
      note = note;
      requestId = requestId;
      periodKey = reserved.usage.periodKey;
      status = #pending;
      at = now;
    };
    Map.set(paymentsById, nhash, pid, pending);
    switch (requestId) { case (?r) Map.set(paymentByRequest, thash, Nat.toText(gid) # ":" # r, pid); case (null) {} };
    let toName = switch (toLabel) { case (?l) l; case (null) shortPrincipal(to.owner) };

    // Invariant 1: `from` is the grant's owner, always.
    let outcome = try {
      #answered(
        await ledgerOf(sp.asset.ledger).icrc2_transfer_from({
          spender_subaccount = null;
          from = { owner = g.owner; subaccount = null };
          to = to;
          amount = amount;
          fee = null;
          memo = ?Text.encodeUtf8("delegation:" # Nat.toText(pid));
          created_at_time = ?Nat64.fromNat(Int.abs(now));
        })
      );
    } catch (e) { #threw(Error.message(e)) };

    let latest = switch (Map.get(grantsById, nhash, gid)) { case (?x) x; case (null) reserved };
    switch (outcome) {
      case (#answered(#Ok(block))) {
        let done = { pending with status = #sent(block) };
        Map.set(paymentsById, nhash, pid, done);
        logEvent(g.owner, ?agent.id, ?gid, "paid", true, "Paid " # amt(g, amount) # " to " # toName # " (block " # Nat.toText(block) # ")" # (switch (note) { case (?n) ": " # n; case (null) "" }));
        cb(#ok(okResult(Json.obj([
          ("message", Json.str("Paid " # amt(g, amount) # " to " # toName # ". Ledger block " # Nat.toText(block) # ".")),
          ("payment", paymentJson(done, latest)),
          ("grant", grantJson(latest, Time.now())),
        ]))));
      };
      case (#answered(#Err(e))) {
        releaseUse(gid, pending.periodKey, amount);
        let why = switch (e) {
          case (#InsufficientAllowance(x)) "The owner's allowance to this registry is " # fmtNum(x.allowance, d) # " " # sp.asset.symbol # ", not enough for this payment plus the fee. The owner needs to approve more (spending_status shows the exact call).";
          case (#InsufficientFunds(x)) "The owner's balance is " # fmtNum(x.balance, d) # " " # sp.asset.symbol # ", not enough for this payment plus the fee.";
          case (#BadFee(x)) "The ledger expects a fee of " # Nat.toText(x.expected_fee) # ".";
          case (#TemporarilyUnavailable) "The ledger is temporarily unavailable; try again with a new request_id.";
          case (#GenericError(x)) "Ledger error " # Nat.toText(x.error_code) # ": " # x.message;
          case (#Duplicate(x)) "The ledger saw this as a duplicate of block " # Nat.toText(x.duplicate_of) # ".";
          case (#TooOld) "The transfer was too old by the time it reached the ledger; try again.";
          case (#CreatedInFuture(_)) "The ledger thinks this transfer is from the future; try again.";
          case (#BadBurn(_)) "The ledger refused it as a burn.";
        };
        Map.set(paymentsById, nhash, pid, { pending with status = #failed(why) });
        logEvent(g.owner, ?agent.id, ?gid, "pay_failed", false, "Ledger refused " # amt(g, amount) # " to " # toName # ": " # why);
        fail(cb, why # " Nothing was paid, and the budget was not used.");
      };
      case (#threw(msg)) {
        // The outcome is unknown. Keeping the reservation is the safe side:
        // releasing budget for money that may have moved is how limits leak.
        let why = "The ledger call failed without an answer (" # msg # "). The payment may or may not have happened; its amount stays counted against the budget. Check the owner's ledger history before retrying.";
        Map.set(paymentsById, nhash, pid, { pending with status = #uncertain(why) });
        logEvent(g.owner, ?agent.id, ?gid, "pay_uncertain", false, amt(g, amount) # " to " # toName # ": " # why);
        fail(cb, why);
      };
    };
  };

  // --- use_permission ---

  /// The grants behind (principal, action), optionally for one owner.
  func actionGrants(agentP : Principal, action : Text, owner : ?Principal) : [(Agent, Grant)] {
    let out = Buffer.Buffer<(Agent, Grant)>(4);
    for (a in agentRecordsFor(agentP).vals()) {
      let ownerOk = switch (owner) { case (?o) a.owner == o; case (null) true };
      if (ownerOk) {
        for (gid in idsOf(grantIdsByAgent, nhash, a.id).vals()) {
          switch (Map.get(grantsById, nhash, gid)) {
            case (?g) {
              switch (g.kind) { case (#action(x)) { if (x.action == action) out.add((a, g)) }; case (#spend(_)) {} };
            };
            case (null) {};
          };
        };
      };
    };
    Buffer.toArray(out);
  };

  func optPrincipalArg(args : McpTypes.JsonValue, field : Text) : { #none; #ok : Principal; #bad : Text } {
    switch (optText(args, field)) {
      case (null) #none;
      case (?t) switch (parsePrincipal(t)) { case (?p) #ok(p); case (null) #bad("'" # field # "' must be a principal.") };
    };
  };

  func usePermissionTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?p = requireAuth(auth, cb) else return;
    let now = Time.now();
    let ?raw = optText(args, "action") else return fail(cb, "'action' is required, e.g. 'contract.sign'.");
    let ?action = validAction(raw) else return fail(cb, "'" # clip(raw, 60) # "' is not a valid action name.");
    let amount = switch (readAmount(args, "amount", actionDecimals)) {
      case (#ok(n)) ?n;
      case (#absent) null;
      case (#bad) return fail(cb, "'amount' must be a positive number with at most 2 decimals.");
    };
    let counterparty = switch (optPrincipalArg(args, "counterparty")) { case (#ok(c)) ?c; case (#none) null; case (#bad(e)) return fail(cb, e) };
    let owner = switch (optPrincipalArg(args, "owner")) { case (#ok(o)) ?o; case (#none) null; case (#bad(e)) return fail(cb, e) };
    let note = optText(args, "note");
    switch (note) { case (?n) { switch (requireLen(n, "note", 1, maxNoteChars)) { case (?e) return fail(cb, e); case (null) {} } }; case (null) {} };
    let onlyGrant = optNat(args, "grant");

    let candidates = Array.filter<(Agent, Grant)>(actionGrants(p, action, owner), func((_, g)) { switch (onlyGrant) { case (?id) g.id == id; case (null) true } });
    if (candidates.size() == 0) {
      // Log to every owner this principal is an agent for — an agent
      // reaching past its grants is exactly what an owner wants to see.
      for (a in agentRecordsFor(p).vals()) {
        let ownerOk = switch (owner) { case (?o) a.owner == o; case (null) true };
        if (ownerOk) logEvent(a.owner, ?a.id, null, "use_refused", false, "Tried '" # action # "' with no grant for it" # (switch (note) { case (?n) ": " # n; case (null) "" }));
      };
      return fail(cb, "Refused: you hold no grant for '" # action # "'. Do not do it; ask your user. (my_grants lists what you hold.)");
    };
    var firstWhy : ?(Agent, Grant, Text) = null;
    for ((a, g) in candidates.vals()) {
      switch (refusal(g, now, amount, counterparty)) {
        case (null) {
          let g2 = recordUse(g, now, switch (amount) { case (?x) x; case (null) 0 });
          let detail = "'" # action # "'" # (switch (amount) { case (?x) " for " # amt(g, x); case (null) "" }) # (switch (counterparty) { case (?c) " with " # shortPrincipal(c); case (null) "" }) # (switch (note) { case (?n) ": " # n; case (null) "" });
          logEvent(g.owner, ?a.id, ?g.id, "action_used", true, detail);
          return cb(#ok(okResult(Json.obj([
            ("allowed", Json.bool(true)),
            ("message", Json.str("Allowed and recorded against grant #" # Nat.toText(g.id) # ". Go ahead.")),
            ("owner", Json.str(Principal.toText(g.owner))),
            ("grant", grantJson(g2, now)),
          ]))));
        };
        case (?(_, why)) { if (firstWhy == null) firstWhy := ?(a, g, why) };
      };
    };
    let ?(a, g, why) = firstWhy else return fail(cb, "Refused.");
    logEvent(g.owner, ?a.id, ?g.id, "use_refused", false, "'" # action # "' refused: " # why);
    cb(#ok(okResult(Json.obj([
      ("allowed", Json.bool(false)),
      ("message", Json.str("Refused: " # why # " Do not do the action; tell your user.")),
      ("grant", Json.int(g.id)),
    ]))));
  };

  // --- check_permission ---

  func checkPermissionTool(args : McpTypes.JsonValue, auth : ?AuthTypes.AuthInfo, cb : ToolCb) : async () {
    let ?checker = requireAuth(auth, cb) else return;
    let now = Time.now();
    let ?agentText = optText(args, "agent") else return fail(cb, "'agent' is required: the agent's principal.");
    let ?agentP = parsePrincipal(agentText) else return fail(cb, "'agent' must be a principal.");
    let ?raw = optText(args, "action") else return fail(cb, "'action' is required.");
    let ?action = validAction(raw) else return fail(cb, "'" # clip(raw, 60) # "' is not a valid action name.");
    let amount = switch (readAmount(args, "amount", actionDecimals)) {
      case (#ok(n)) ?n;
      case (#absent) null;
      case (#bad) return fail(cb, "'amount' must be a positive number with at most 2 decimals.");
    };
    let counterparty = switch (optPrincipalArg(args, "counterparty")) { case (#ok(c)) ?c; case (#none) null; case (#bad(e)) return fail(cb, e) };
    let owner = switch (optPrincipalArg(args, "owner")) { case (#ok(o)) ?o; case (#none) null; case (#bad(e)) return fail(cb, e) };

    let candidates = actionGrants(agentP, action, owner);
    if (candidates.size() == 0) {
      // No owner is named, so nothing leaks about who this principal serves.
      return cb(#ok(okResult(Json.obj([
        ("allowed", Json.bool(false)),
        ("reason", Json.str("no grant")),
        ("message", Json.str("No owner has granted this principal '" # action # "' here.")),
      ]))));
    };
    var firstCode : ?(Agent, Grant, Text) = null;
    for ((a, g) in candidates.vals()) {
      switch (refusal(g, now, amount, counterparty)) {
        case (null) {
          logEvent(g.owner, ?a.id, ?g.id, "checked", true, shortPrincipal(checker) # " checked '" # action # "' → allowed");
          return cb(#ok(okResult(Json.obj([
            ("allowed", Json.bool(true)),
            ("owner", Json.str(Principal.toText(g.owner))),
            ("agent_name", Json.str(a.name)),
            ("grant", Json.int(g.id)),
            ("purpose", Json.str(g.purpose)),
            ("expires", Json.str(fmtUtc(g.expiresAt))),
            ("message", Json.str("Allowed: " # Principal.toText(g.owner) # " authorized this agent to '" # action # "' until " # fmtUtc(g.expiresAt) # ".")),
          ]))));
        };
        case (?(code, _)) { if (firstCode == null) firstCode := ?(a, g, code) };
      };
    };
    let ?(a, g, code) = firstCode else return fail(cb, "Refused.");
    logEvent(g.owner, ?a.id, ?g.id, "checked", false, shortPrincipal(checker) # " checked '" # action # "' → not allowed (" # code # ")");
    cb(#ok(okResult(Json.obj([
      ("allowed", Json.bool(false)),
      ("reason", Json.str(code)),
      ("owner", Json.str(Principal.toText(g.owner))),
      ("message", Json.str("Not allowed (" # code # ").")),
    ]))));
  };

  // --- SDK CONFIG & HTTP WIRING ---

  transient let mcpConfig : McpTypes.McpConfig = {
    self = Principal.fromActor(self);
    allowanceUrl = null;
    serverInfo = { name = "delegation-registry"; title = "Agent Delegation Registry"; version = "0.1.0" };
    resources = [];
    resourceReader = func(uri) { Map.get(appContext.resourceContents, Map.thash, uri) };
    tools = tools;
    toolImplementations = [
      ("add_agent", addAgentTool),
      ("list_agents", listAgentsTool),
      ("set_agent_status", setAgentStatusTool),
      ("new_agent_key", newAgentKeyTool),
      ("grant_spend", grantSpendTool),
      ("grant_action", grantActionTool),
      ("revoke_grant", revokeGrantTool),
      ("list_grants", listGrantsTool),
      ("spending_status", spendingStatusTool),
      ("activity", activityTool),
      ("my_grants", myGrantsTool),
      ("pay", payTool),
      ("use_permission", usePermissionTool),
      ("check_permission", checkPermissionTool),
    ];
    beacon = ?beaconContext;
  };

  transient let mcpServer = Mcp.createServer(mcpConfig);

  private func _create_http_context() : HttpHandler.Context {
    return {
      self = Principal.fromActor(self);
      active_streams = appContext.activeStreams;
      mcp_server = mcpServer;
      streaming_callback = http_request_streaming_callback;
      auth = ?authContext;
      http_asset_cache = ?http_assets.cache;
      mcp_path = ?"/mcp";
    };
  };

  public query func http_request(req : SrvTypes.HttpRequest) : async SrvTypes.HttpResponse {
    let ctx : HttpHandler.Context = _create_http_context();
    switch (HttpHandler.http_request(ctx, req)) {
      case (?mcpResponse) { mcpResponse };
      case (null) {
        if (req.url == "/") {
          // Query responses need certification on the non-raw gateway; punt to an
          // update call, which is exempt.
          { status_code = 204; headers = []; body = Blob.fromArray([]); upgrade = ?true; streaming_strategy = null };
        } else {
          { status_code = 404; headers = []; body = Blob.fromArray([]); upgrade = null; streaming_strategy = null };
        };
      };
    };
  };

  public shared func http_request_update(req : SrvTypes.HttpRequest) : async SrvTypes.HttpResponse {
    let ctx : HttpHandler.Context = _create_http_context();
    switch (await HttpHandler.http_request_update(ctx, req)) {
      case (?res) { res };
      case (null) {
        if (req.url == "/") {
          {
            status_code = 200;
            headers = [("Content-Type", "text/html")];
            body = Text.encodeUtf8("<h1>Agent Delegation Registry MCP Server</h1><p>Scoped, expiring, revocable grants from a principal to an agent — with ckUSDC spending the registry enforces on-chain. MCP endpoint at <code>/mcp</code>. Authenticate with an <code>x-api-key</code> header.</p>");
            upgrade = null;
            streaming_strategy = null;
          };
        } else {
          { status_code = 404; headers = []; body = Blob.fromArray([]); upgrade = null; streaming_strategy = null };
        };
      };
    };
  };

  public query func http_request_streaming_callback(token : HttpTypes.StreamingToken) : async ?HttpTypes.StreamingCallbackResponse {
    let ctx : HttpHandler.Context = _create_http_context();
    return HttpHandler.http_request_streaming_callback(ctx, token);
  };

  system func preupgrade() {
    stable_http_assets := HttpAssets.preupgrade(http_assets);
  };

  system func postupgrade() {
    HttpAssets.postupgrade(http_assets);
  };

  /// Mint a stable API key bound to the caller's principal.
  /// The raw key is returned once and never stored in plaintext.
  public shared (msg) func create_my_api_key(name : Text, scopes : [Text]) : async Text {
    return await ApiKey.create_my_api_key(authContext, msg.caller, name, scopes);
  };

  /// Deployer-only: allow another ICRC-2 ledger (used for the local test
  /// ledger). Not an MCP tool, on purpose.
  public shared (msg) func admin_allow_asset(ledger : Text, symbol : Text, decimals : Nat8, capMinor : Nat) : async () {
    assert (msg.caller == deployer);
    Map.set(allowedAssets, thash, ledger, { symbol = symbol; decimals = decimals; capMinor = capMinor });
  };
};
