// ZATCA Phase 2 (Fatoora) e-invoicing core: keys, CSR, UBL 2.1 invoice XML, invoice hash, cryptographic stamp, QR.
// Pure TypeScript — runs in the Supabase Edge Function (Deno) and in Node for testing.
import { secp256k1 } from "npm:@noble/curves@1.9.7/secp256k1";
import { sha256 } from "npm:@noble/hashes@1.8.0/sha256";

/* ---------------- bytes ---------------- */
const enc = new TextEncoder();
export const utf8 = (s: string) => enc.encode(s);
export function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) (out.set(p, o), (o += p.length));
  return out;
}
export function b64(bytes: Uint8Array) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
export function unb64(s: string) {
  const bin = atob(s.replace(/\s+/g, ""));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (h: string) => Uint8Array.from(h.match(/.{2}/g)!.map((x) => parseInt(x, 16)));

/* ---------------- DER ---------------- */
function derLen(n: number) {
  if (n < 0x80) return Uint8Array.of(n);
  const b: number[] = [];
  while (n > 0) (b.unshift(n & 0xff), (n >>= 8));
  return Uint8Array.of(0x80 | b.length, ...b);
}
const tlv = (tag: number, body: Uint8Array) => concat(Uint8Array.of(tag), derLen(body.length), body);
const seq = (...items: Uint8Array[]) => tlv(0x30, concat(...items));
const set = (...items: Uint8Array[]) => tlv(0x31, concat(...items));
const int = (n: number) => tlv(0x02, Uint8Array.of(n));
const octet = (b: Uint8Array) => tlv(0x04, b);
const bitstr = (b: Uint8Array) => tlv(0x03, concat(Uint8Array.of(0), b));
const utf8str = (s: string) => tlv(0x0c, utf8(s));
const printable = (s: string) => tlv(0x13, utf8(s));
const bool = (v: boolean) => tlv(0x01, Uint8Array.of(v ? 0xff : 0));
function oid(dotted: string) {
  const p = dotted.split(".").map(Number);
  const out: number[] = [40 * p[0] + p[1]];
  for (const v of p.slice(2)) {
    const b: number[] = [v & 0x7f];
    let x = v >>> 7;
    while (x > 0) (b.unshift((x & 0x7f) | 0x80), (x >>>= 7));
    out.push(...b);
  }
  return tlv(0x06, Uint8Array.from(out));
}
const attr = (o: string, value: Uint8Array) => set(seq(oid(o), value));

/* ---------------- keys and CSR ---------------- */
export function newPrivateKey() {
  return hex(secp256k1.utils.randomPrivateKey());
}

export function publicKeySpki(privHex: string) {
  const pub = secp256k1.getPublicKey(unhex(privHex), false); // 04 || X || Y
  return seq(seq(oid("1.2.840.10045.2.1"), oid("1.3.132.0.10")), bitstr(pub));
}

/** ECDSA-SHA256 over `data` (the data is hashed once here), DER signature. */
export function ecdsaSign(privHex: string, data: Uint8Array) {
  return secp256k1.sign(sha256(data), unhex(privHex)).toDERRawBytes();
}

export interface EgsInfo {
  /** e.g. TST-886431145-300000000000003 */
  commonName: string;
  /** VAT registration number (15 digits) */
  vat: string;
  organization: string;
  branch: string;
  /** "1-<solution>|2-<model/version>|3-<device uuid>" */
  serial: string;
  /** "1100" standard + simplified */
  invoiceTypes: string;
  /** short national address, e.g. "RRRD2929" */
  location: string;
  industry: string;
  /** TSTZATCA-Code-Signing (developer sandbox), PREZATCA-Code-Signing (simulation), ZATCA-Code-Signing (production) */
  template: string;
}

/** PKCS#10 certificate signing request in ZATCA's format, returned as the base64 of its PEM text (what the API wants). */
export function buildCsr(privHex: string, e: EgsInfo) {
  const subject = seq(attr("2.5.4.6", printable("SA")), attr("2.5.4.11", utf8str(e.branch)), attr("2.5.4.10", utf8str(e.organization)), attr("2.5.4.3", utf8str(e.commonName)));
  const dirName = seq(
    attr("2.5.4.4", utf8str(e.serial)),
    attr("0.9.2342.19200300.100.1.1", utf8str(e.vat)),
    attr("2.5.4.12", utf8str(e.invoiceTypes)),
    attr("2.5.4.26", utf8str(e.location)),
    attr("2.5.4.15", utf8str(e.industry)),
  );
  const extensions = seq(
    seq(oid("1.3.6.1.4.1.311.20.2"), octet(printable(e.template))),
    seq(oid("2.5.29.17"), octet(seq(tlv(0xa4, dirName)))),
  );
  const attributes = tlv(0xa0, seq(oid("1.2.840.113549.1.9.14"), set(extensions)));
  const info = seq(int(0), subject, publicKeySpki(privHex), attributes);
  const sig = ecdsaSign(privHex, info);
  const csr = seq(info, seq(oid("1.2.840.10045.4.3.2")), bitstr(sig));
  const body = b64(csr).match(/.{1,64}/g)!.join("\n");
  const pem = `-----BEGIN CERTIFICATE REQUEST-----\n${body}\n-----END CERTIFICATE REQUEST-----`;
  return { pem, base64: b64(utf8(pem)) };
}
// keep the helper referenced for future extensions (basicConstraints etc.)
void bool;

/* ---------------- certificate reading ---------------- */
interface Node {
  tag: number;
  start: number;
  hdr: number;
  len: number;
}
function read(b: Uint8Array, at: number): Node {
  const tag = b[at];
  let len = b[at + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[at + 2 + i];
    hdr = 2 + n;
  }
  return { tag, start: at, hdr, len };
}
function children(b: Uint8Array, n: Node) {
  const out: Node[] = [];
  let p = n.start + n.hdr;
  const end = p + n.len;
  while (p < end) {
    const c = read(b, p);
    out.push(c);
    p = c.start + c.hdr + c.len;
  }
  return out;
}
const body = (b: Uint8Array, n: Node) => b.subarray(n.start + n.hdr, n.start + n.hdr + n.len);
const whole = (b: Uint8Array, n: Node) => b.subarray(n.start, n.start + n.hdr + n.len);
function oidText(bytes: Uint8Array) {
  const out = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (const x of bytes.subarray(1)) {
    v = v * 128 + (x & 0x7f);
    if (!(x & 0x80)) (out.push(v), (v = 0));
  }
  return out.join(".");
}
const NAMES: Record<string, string> = { "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.7": "L", "2.5.4.8": "ST", "0.9.2342.19200300.100.1.25": "DC", "1.2.840.113549.1.9.1": "E" };

export interface CertInfo {
  /** base64 certificate body (no PEM header) */
  base64: string;
  issuer: string;
  serial: string;
  /** DER SubjectPublicKeyInfo — QR tag 8 */
  publicKey: Uint8Array;
  /** certificate signature value — QR tag 9 */
  signature: Uint8Array;
  /** base64(hex(sha256(certificate base64 text))) — as ZATCA's signed properties expect */
  hash: string;
}

export function readCertificate(certBase64: string): CertInfo {
  const clean = certBase64.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = unb64(clean);
  const root = read(der, 0);
  const [tbs, , sigNode] = children(der, root);
  const t = children(der, tbs);
  let i = 0;
  if (t[0].tag === 0xa0) i = 1; // version
  const serialBytes = body(der, t[i]);
  const issuerNode = t[i + 2];
  const spkiNode = t[i + 5];
  const rdns = children(der, issuerNode).map((rdn) => {
    const atv = children(der, children(der, rdn)[0]);
    const name = NAMES[oidText(body(der, atv[0]))] ?? oidText(body(der, atv[0]));
    return `${name}=${new TextDecoder().decode(body(der, atv[1]))}`;
  });
  let serial = 0n;
  for (const x of serialBytes) serial = serial * 256n + BigInt(x);
  return {
    base64: clean,
    issuer: rdns.reverse().join(", "),
    serial: serial.toString(10),
    publicKey: whole(der, spkiNode).slice(),
    signature: body(der, sigNode).slice(1),
    hash: b64(utf8(hex(sha256(utf8(clean))))),
  };
}

/* ---------------- invoice XML ---------------- */
const esc = (s: unknown) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const escAttr = (s: unknown) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
/** element with attributes in canonical (sorted) order and explicit end tags, as C14N writes them */
function el(name: string, attrs: Record<string, string> | null, ...kids: (string | false | null | undefined)[]) {
  const a = attrs
    ? Object.keys(attrs)
        .sort()
        .map((k) => ` ${k}="${escAttr(attrs[k])}"`)
        .join("")
    : "";
  return `<${name}${a}>${kids.filter(Boolean).join("")}</${name}>`;
}
const t = (name: string, value: unknown, attrs: Record<string, string> | null = null) => (value === undefined || value === null || value === "" ? "" : el(name, attrs, esc(value)));
const amt = (n: number) => (Math.round((n + Number.EPSILON) * 100) / 100).toFixed(2);
const r2 = (n: number) => Math.round((n + Number.EPSILON) * 100) / 100;

export interface Address {
  street: string;
  building: string;
  district: string;
  city: string;
  postal: string;
  country?: string;
}
export interface Party {
  name: string;
  vat?: string;
  crn?: string;
  address?: Partial<Address>;
}
export interface InvoiceLine {
  name: string;
  qty: number;
  price: number;
  vatRate: number; // 15
}
export interface InvoiceInput {
  number: string;
  uuid: string;
  issueDate: string; // YYYY-MM-DD
  issueTime: string; // HH:mm:ss
  kind: "standard" | "simplified";
  docType: "388" | "381" | "383"; // invoice, credit note, debit note
  /** for credit/debit notes */
  refNumber?: string;
  reason?: string;
  icv: number;
  pih: string;
  seller: Party & { crn: string; address: Address };
  buyer?: Party;
  supplyDate?: string;
  paymentCode?: string; // 10 cash, 30 credit, 42 bank transfer, 48 card
  lines: InvoiceLine[];
}

export function totals(inv: InvoiceInput) {
  const lines = inv.lines.map((l, i) => {
    const net = r2(l.qty * l.price);
    const vat = r2((net * l.vatRate) / 100);
    return { ...l, id: i + 1, net, vat };
  });
  const net = r2(lines.reduce((s, l) => s + l.net, 0));
  const byRate = new Map<number, number>();
  lines.forEach((l) => byRate.set(l.vatRate, r2((byRate.get(l.vatRate) ?? 0) + l.net)));
  const subtotals = [...byRate.entries()].map(([rate, taxable]) => ({ rate, taxable, vat: r2((taxable * rate) / 100) }));
  const vat = r2(subtotals.reduce((s, x) => s + x.vat, 0));
  return { lines, net, vat, gross: r2(net + vat), subtotals };
}

function address(a: Partial<Address> | undefined) {
  if (!a) return "";
  return el(
    "cac:PostalAddress",
    null,
    t("cbc:StreetName", a.street),
    t("cbc:BuildingNumber", a.building),
    t("cbc:CitySubdivisionName", a.district),
    t("cbc:CityName", a.city),
    t("cbc:PostalZone", a.postal),
    el("cac:Country", null, t("cbc:IdentificationCode", a.country || "SA")),
  );
}

const SAR = { currencyID: "SAR" };
const NS = ' xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"';

/** Builds the invoice. With `stamp` the full signed document; without it, the exact canonical text that is hashed. */
export function invoiceXml(inv: InvoiceInput, stamp?: { extensions: string; qr: string }) {
  const T = totals(inv);
  const isStd = inv.kind === "standard";
  const b = inv.buyer;
  const parts = [
    stamp ? el("ext:UBLExtensions", null, stamp.extensions) : "",
    t("cbc:ProfileID", "reporting:1.0"),
    t("cbc:ID", inv.number),
    t("cbc:UUID", inv.uuid),
    t("cbc:IssueDate", inv.issueDate),
    t("cbc:IssueTime", inv.issueTime),
    t("cbc:InvoiceTypeCode", inv.docType, { name: isStd ? "0100000" : "0200000" }),
    t("cbc:DocumentCurrencyCode", "SAR"),
    t("cbc:TaxCurrencyCode", "SAR"),
    inv.docType !== "388" && inv.refNumber ? el("cac:BillingReference", null, el("cac:InvoiceDocumentReference", null, t("cbc:ID", inv.refNumber))) : "",
    el("cac:AdditionalDocumentReference", null, t("cbc:ID", "ICV"), t("cbc:UUID", String(inv.icv))),
    el("cac:AdditionalDocumentReference", null, t("cbc:ID", "PIH"), el("cac:Attachment", null, t("cbc:EmbeddedDocumentBinaryObject", inv.pih, { mimeCode: "text/plain" }))),
    stamp ? el("cac:AdditionalDocumentReference", null, t("cbc:ID", "QR"), el("cac:Attachment", null, t("cbc:EmbeddedDocumentBinaryObject", stamp.qr, { mimeCode: "text/plain" }))) : "",
    stamp ? el("cac:Signature", null, t("cbc:ID", "urn:oasis:names:specification:ubl:signature:Invoice"), t("cbc:SignatureMethod", "urn:oasis:names:specification:ubl:dsig:enveloped:xades")) : "",
    el(
      "cac:AccountingSupplierParty",
      null,
      el(
        "cac:Party",
        null,
        el("cac:PartyIdentification", null, t("cbc:ID", inv.seller.crn, { schemeID: "CRN" })),
        address(inv.seller.address),
        el("cac:PartyTaxScheme", null, t("cbc:CompanyID", inv.seller.vat), el("cac:TaxScheme", null, t("cbc:ID", "VAT"))),
        el("cac:PartyLegalEntity", null, t("cbc:RegistrationName", inv.seller.name)),
      ),
    ),
    el(
      "cac:AccountingCustomerParty",
      null,
      b
        ? el(
            "cac:Party",
            null,
            b.crn && !b.vat ? el("cac:PartyIdentification", null, t("cbc:ID", b.crn, { schemeID: "CRN" })) : "",
            address(b.address),
            b.vat ? el("cac:PartyTaxScheme", null, t("cbc:CompanyID", b.vat), el("cac:TaxScheme", null, t("cbc:ID", "VAT"))) : "",
            el("cac:PartyLegalEntity", null, t("cbc:RegistrationName", b.name)),
          )
        : "",
    ),
    isStd || inv.supplyDate ? el("cac:Delivery", null, t("cbc:ActualDeliveryDate", inv.supplyDate || inv.issueDate)) : "",
    el("cac:PaymentMeans", null, t("cbc:PaymentMeansCode", inv.paymentCode || "30"), inv.docType !== "388" ? t("cbc:InstructionNote", inv.reason || "Correction") : ""),
    el("cac:TaxTotal", null, t("cbc:TaxAmount", amt(T.vat), SAR)),
    el(
      "cac:TaxTotal",
      null,
      t("cbc:TaxAmount", amt(T.vat), SAR),
      ...T.subtotals.map((s) =>
        el(
          "cac:TaxSubtotal",
          null,
          t("cbc:TaxableAmount", amt(s.taxable), SAR),
          t("cbc:TaxAmount", amt(s.vat), SAR),
          el("cac:TaxCategory", null, t("cbc:ID", s.rate > 0 ? "S" : "Z"), t("cbc:Percent", s.rate.toFixed(2)), s.rate > 0 ? "" : t("cbc:TaxExemptionReasonCode", "VATEX-SA-32"), el("cac:TaxScheme", null, t("cbc:ID", "VAT"))),
        ),
      ),
    ),
    el(
      "cac:LegalMonetaryTotal",
      null,
      t("cbc:LineExtensionAmount", amt(T.net), SAR),
      t("cbc:TaxExclusiveAmount", amt(T.net), SAR),
      t("cbc:TaxInclusiveAmount", amt(T.gross), SAR),
      t("cbc:AllowanceTotalAmount", "0.00", SAR),
      t("cbc:PrepaidAmount", "0.00", SAR),
      t("cbc:PayableAmount", amt(T.gross), SAR),
    ),
    ...T.lines.map((l) =>
      el(
        "cac:InvoiceLine",
        null,
        t("cbc:ID", String(l.id)),
        t("cbc:InvoicedQuantity", String(l.qty), { unitCode: "PCE" }),
        t("cbc:LineExtensionAmount", amt(l.net), SAR),
        el("cac:TaxTotal", null, t("cbc:TaxAmount", amt(l.vat), SAR), t("cbc:RoundingAmount", amt(l.net + l.vat), SAR)),
        el("cac:Item", null, t("cbc:Name", l.name), el("cac:ClassifiedTaxCategory", null, t("cbc:ID", l.vatRate > 0 ? "S" : "Z"), t("cbc:Percent", l.vatRate.toFixed(2)), el("cac:TaxScheme", null, t("cbc:ID", "VAT")))),
        el("cac:Price", null, t("cbc:PriceAmount", amt(l.price), SAR)),
      ),
    ),
  ];
  const doc = `<Invoice${NS}>${parts.filter(Boolean).join("")}</Invoice>`;
  return stamp ? `<?xml version="1.0" encoding="UTF-8"?>\n${doc}` : doc;
}

/* ---------------- QR (TLV) ---------------- */
function tag(n: number, v: Uint8Array) {
  if (v.length > 255) throw new Error(`QR tag ${n} too long`);
  return concat(Uint8Array.of(n, v.length), v);
}
export function qrTlv(f: { seller: string; vat: string; timestamp: string; total: string; vatTotal: string; hash: string; signature: string; publicKey: Uint8Array; certSignature?: Uint8Array }) {
  return b64(
    concat(
      tag(1, utf8(f.seller)),
      tag(2, utf8(f.vat)),
      tag(3, utf8(f.timestamp)),
      tag(4, utf8(f.total)),
      tag(5, utf8(f.vatTotal)),
      tag(6, utf8(f.hash)),
      tag(7, utf8(f.signature)),
      tag(8, f.publicKey),
      ...(f.certSignature ? [tag(9, f.certSignature)] : []),
    ),
  );
}

/* ---------------- signing ---------------- */
export function signInvoice(inv: InvoiceInput, privHex: string, cert: CertInfo, signingTime = new Date().toISOString().slice(0, 19)) {
  const pure = invoiceXml(inv);
  const hashBytes = sha256(utf8(pure));
  const invoiceHash = b64(hashBytes);
  const signature = b64(ecdsaSign(privHex, hashBytes));
  const T = totals(inv);

  const DS = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"';
  const sp = (withNs: boolean) => {
    const ns = withNs ? ` ${DS}` : "";
    return (
      `<xades:SignedProperties${withNs ? ' xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"' : ""} Id="xadesSignedProperties">` +
      `<xades:SignedSignatureProperties><xades:SigningTime>${signingTime}</xades:SigningTime><xades:SigningCertificate><xades:Cert><xades:CertDigest>` +
      `<ds:DigestMethod${ns} Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"${withNs ? "/>" : "></ds:DigestMethod>"}` +
      `<ds:DigestValue${ns}>${cert.hash}</ds:DigestValue></xades:CertDigest><xades:IssuerSerial>` +
      `<ds:X509IssuerName${ns}>${esc(cert.issuer)}</ds:X509IssuerName><ds:X509SerialNumber${ns}>${cert.serial}</ds:X509SerialNumber>` +
      `</xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties>`
    );
  };
  const signedPropsHash = b64(utf8(hex(sha256(utf8(sp(true))))));
  const extensions =
    `<ext:UBLExtension><ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI><ext:ExtensionContent>` +
    `<sig:UBLDocumentSignatures xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2" xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2" xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2">` +
    `<sac:SignatureInformation><cbc:ID>urn:oasis:names:specification:ubl:signature:1</cbc:ID><sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID>` +
    `<ds:Signature ${DS} Id="signature"><ds:SignedInfo>` +
    `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod>` +
    `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod>` +
    `<ds:Reference Id="invoiceSignedData" URI=""><ds:Transforms>` +
    `<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath></ds:Transform>` +
    `<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath></ds:Transform>` +
    `<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])</ds:XPath></ds:Transform>` +
    `<ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:Transform></ds:Transforms>` +
    `<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>${invoiceHash}</ds:DigestValue></ds:Reference>` +
    `<ds:Reference Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties" URI="#xadesSignedProperties"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>${signedPropsHash}</ds:DigestValue></ds:Reference>` +
    `</ds:SignedInfo><ds:SignatureValue>${signature}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert.base64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `<ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="signature">${sp(false)}</xades:QualifyingProperties></ds:Object>` +
    `</ds:Signature></sac:SignatureInformation></sig:UBLDocumentSignatures></ext:ExtensionContent></ext:UBLExtension>`;

  const qr = qrTlv({
    seller: inv.seller.name,
    vat: inv.seller.vat!,
    timestamp: `${inv.issueDate}T${inv.issueTime}`,
    total: amt(T.gross),
    vatTotal: amt(T.vat),
    hash: invoiceHash,
    signature,
    publicKey: cert.publicKey,
    certSignature: inv.kind === "simplified" ? cert.signature : undefined,
  });
  const xml = invoiceXml(inv, { extensions, qr });
  return { xml, invoiceHash, qr, signature, totals: T };
}

/** Hash of "0" — the PIH of the very first invoice. */
export const FIRST_PIH = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==";

// ---- ZATCA edge function: connect the e-invoicing device, run compliance checks, clear / report invoices ----
// (core.ts is placed above this file when the function is bundled into one index.ts)
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const BASE: Record<string, string> = {
  sandbox: "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal",
  simulation: "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation",
  production: "https://gw-fatoora.zatca.gov.sa/e-invoicing/core",
};
const TEMPLATE: Record<string, string> = { sandbox: "TSTZATCA-Code-Signing", simulation: "PREZATCA-Code-Signing", production: "ZATCA-Code-Signing" };

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

async function zatca(env: string, path: string, body: unknown, headers: Record<string, string>) {
  const res = await fetch(BASE[env] + path, {
    method: "POST",
    headers: { Accept: "application/json", "Accept-Language": "en", "Accept-Version": "V2", "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text.slice(0, 2000) };
  }
  return { status: res.status, data };
}
const basic = (token: string, secret: string) => ({ Authorization: "Basic " + btoa(`${token}:${secret}`) });
const certOf = (token: string) => readCertificate(atob(token));

function issueParts(d = new Date()) {
  // Saudi time for the invoice date and time
  const k = new Date(d.getTime() + 3 * 3600_000).toISOString();
  return { date: k.slice(0, 10), time: k.slice(11, 19) };
}

function seller(s: any) {
  return {
    name: s.zatca_seller_name || s.company_name,
    vat: String(s.vat_number || "").trim(),
    crn: String(s.cr_number || "").trim(),
    address: { street: s.zatca_street, building: s.zatca_building, district: s.zatca_district, city: s.zatca_city || "Jeddah", postal: s.zatca_postal },
  };
}
function missingSeller(s: any) {
  const m: string[] = [];
  if (!/^3\d{13}3$/.test(String(s.vat_number || "").trim())) m.push("company VAT number (15 digits, starts and ends with 3)");
  if (!s.cr_number) m.push("CR number");
  if (!s.zatca_street) m.push("street");
  if (!/^\d{4}$/.test(String(s.zatca_building || ""))) m.push("building number (4 digits)");
  if (!s.zatca_district) m.push("district");
  if (!/^\d{5}$/.test(String(s.zatca_postal || ""))) m.push("postal code (5 digits)");
  return m;
}

function sampleDocs(s: any, egsUuid: string) {
  const sel = seller(s);
  const buyer = { name: "Compliance Test Buyer Co.", vat: "399999999800003", address: { street: "King Fahd Road", building: "1234", district: "Al Olaya", city: "Riyadh", postal: "12211" } };
  const { date, time } = issueParts();
  const out: InvoiceInput[] = [];
  let n = 0;
  for (const kind of ["standard", "simplified"] as const)
    for (const docType of ["388", "381", "383"] as const) {
      n++;
      out.push({
        number: `CMP-${n}`,
        uuid: crypto.randomUUID(),
        issueDate: date,
        issueTime: time,
        kind,
        docType,
        refNumber: docType === "388" ? undefined : "CMP-1",
        reason: docType === "381" ? "Returned items" : docType === "383" ? "Price adjustment" : undefined,
        icv: n,
        pih: FIRST_PIH,
        seller: sel as any,
        buyer: kind === "standard" ? buyer : { name: "Walk-in customer" },
        supplyDate: date,
        paymentCode: "10",
        lines: [{ name: "Mechanical works", qty: 1, price: 100, vatRate: 15 }],
      });
    }
  void egsUuid;
  return out;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const url = Deno.env.get("SUPABASE_URL")!;
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const admin = createClient(url, service, { auth: { persistSession: false } });
    const jwt = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");

    /* ---------- self test on ZATCA's developer sandbox only (no company data, nothing saved) ---------- */
    if (jwt === service) {
      const tb = await req.json().catch(() => ({}));
      if (tb.action !== "selftest") return json({ error: "Unknown action" }, 400);
      const fake: any = { company_name: "Shahin Test Est.", vat_number: "399999999900003", cr_number: "1010010000", zatca_street: "Prince Majid Street", zatca_building: "7689", zatca_district: "Al Aziziyah", zatca_city: "Jeddah", zatca_postal: "23342", zatca_short_address: "JEDA7689" };
      const key = newPrivateKey();
      const egsUuid = crypto.randomUUID();
      const csr = buildCsr(key, { commonName: "TST-886431145-399999999900003", vat: fake.vat_number, organization: fake.company_name, branch: "Head Office", serial: `1-ShahinERP|2-1.12|3-${egsUuid}`, invoiceTypes: "1100", location: fake.zatca_short_address, industry: "Construction", template: TEMPLATE.sandbox });
      const c1 = await zatca("sandbox", "/compliance", { csr: csr.base64 }, { OTP: "123345" });
      if (!c1.data?.binarySecurityToken) return json({ step: "compliance CSID", c1 });
      const tok = c1.data.binarySecurityToken, sec = c1.data.secret;
      const cert = certOf(tok);
      const out: any[] = [];
      let pih = FIRST_PIH;
      for (const doc of sampleDocs(fake, egsUuid)) {
        doc.pih = pih;
        const sg = signInvoice(doc, key, cert);
        const r = await zatca("sandbox", "/compliance/invoices", { invoiceHash: sg.invoiceHash, uuid: doc.uuid, invoice: b64(utf8(sg.xml)) }, basic(tok, sec));
        pih = sg.invoiceHash;
        out.push({ doc: `${doc.kind} ${doc.docType}`, http: r.status, v: r.data?.validationResults ?? r.data, res: r.data?.clearanceStatus || r.data?.reportingStatus });
      }
      const p = await zatca("sandbox", "/production/csids", { compliance_request_id: String(c1.data.requestID) }, basic(tok, sec));
      const live: any[] = [];
      if (p.data?.binarySecurityToken) {
        const pc = certOf(p.data.binarySecurityToken);
        let ph = FIRST_PIH;
        for (const doc of sampleDocs(fake, egsUuid).filter((d) => d.docType === "388")) {
          doc.pih = ph;
          const sg = signInvoice(doc, key, pc);
          const simp = doc.kind === "simplified";
          const r = await zatca("sandbox", simp ? "/invoices/reporting/single" : "/invoices/clearance/single", { invoiceHash: sg.invoiceHash, uuid: doc.uuid, invoice: b64(utf8(sg.xml)) }, { ...basic(p.data.binarySecurityToken, p.data.secret), "Clearance-Status": simp ? "0" : "1" });
          ph = sg.invoiceHash;
          live.push({ doc: doc.kind, http: r.status, status: r.data?.clearanceStatus || r.data?.reportingStatus, v: r.data?.validationResults, cleared: !!r.data?.clearedInvoice });
        }
      }
      return json({ compliance: out, production: { http: p.status, ok: !!p.data?.binarySecurityToken, err: p.data?.binarySecurityToken ? undefined : p.data }, live });
    }

    const { data: u } = await admin.auth.getUser(jwt);
    if (!u?.user) return json({ error: "Please sign in again." }, 401);
    const { data: me } = await admin.from("profiles").select("company_id, role, status, full_name").eq("user_id", u.user.id).maybeSingle();
    if (!me || me.status !== "Active" || !["admin", "accountant"].includes(me.role)) return json({ error: "Only the owner, an admin or the accountant can use ZATCA." }, 403);
    const company = me.company_id;
    const body = await req.json().catch(() => ({}));
    const { data: settings } = await admin.from("settings").select("*").eq("company_id", company).maybeSingle();
    const s: any = settings || {};

    /* ---------- connect the device: CSR -> compliance CSID -> compliance checks -> production CSID ---------- */
    if (body.action === "onboard") {
      if (me.role !== "admin") return json({ error: "Only the owner or an admin can connect ZATCA." }, 403);
      const env = ["sandbox", "simulation", "production"].includes(body.env) ? body.env : "sandbox";
      const otp = String(body.otp || (env === "sandbox" ? "123345" : "")).trim();
      if (!/^\d{6}$/.test(otp)) return json({ error: "Enter the 6-digit OTP from the Fatoora portal." }, 400);
      const missing = missingSeller(s);
      if (missing.length) return json({ error: "Fill these in Settings → ZATCA first: " + missing.join(", ") }, 400);

      const key = newPrivateKey();
      const egsUuid = crypto.randomUUID();
      const vat = String(s.vat_number).trim();
      const commonName = `${env === "production" ? "" : "TST-"}ShahinERP-${vat}`;
      const csr = buildCsr(key, {
        commonName,
        vat,
        organization: seller(s).name,
        branch: s.zatca_branch || "Head Office",
        serial: `1-ShahinERP|2-1.12|3-${egsUuid}`,
        invoiceTypes: "1100",
        location: s.zatca_short_address || `${s.zatca_building} ${s.zatca_street}`.slice(0, 40),
        industry: s.zatca_industry || "Construction",
        template: TEMPLATE[env],
      });
      const c1 = await zatca(env, "/compliance", { csr: csr.base64 }, { OTP: otp });
      if (c1.status !== 200 || !c1.data?.binarySecurityToken) return json({ error: "ZATCA did not accept the request", step: "compliance CSID", zatca: c1 }, 400);
      const ccsid = { token: c1.data.binarySecurityToken as string, secret: c1.data.secret as string, request: String(c1.data.requestID) };
      const cert = certOf(ccsid.token);

      // compliance checks: one of each document the device will issue
      const checks: any[] = [];
      let pih = FIRST_PIH;
      for (const doc of sampleDocs(s, egsUuid)) {
        doc.pih = pih;
        const signed = signInvoice(doc, key, cert);
        const r = await zatca(env, "/compliance/invoices", { invoiceHash: signed.invoiceHash, uuid: doc.uuid, invoice: b64(utf8(signed.xml)) }, basic(ccsid.token, ccsid.secret));
        pih = signed.invoiceHash;
        checks.push({
          doc: `${doc.kind} ${doc.docType}`,
          http: r.status,
          status: r.data?.validationResults?.status,
          result: r.data?.clearanceStatus || r.data?.reportingStatus,
          errors: r.data?.validationResults?.errorMessages ?? [],
          warnings: r.data?.validationResults?.warningMessages ?? [],
        });
      }
      const passed = checks.every((c) => c.http === 200 || c.http === 202);
      await admin.from("zatca_egs").upsert({
        company_id: company,
        env,
        egs_uuid: egsUuid,
        common_name: commonName,
        private_key: key,
        ccsid_token: ccsid.token,
        ccsid_secret: ccsid.secret,
        ccsid_request_id: ccsid.request,
        compliance: checks,
        status: passed ? "Compliance passed" : "Compliance failed",
        updated_at: new Date().toISOString(),
      });
      if (!passed) return json({ error: "ZATCA compliance checks did not pass", checks }, 400);

      const p = await zatca(env, "/production/csids", { compliance_request_id: ccsid.request }, basic(ccsid.token, ccsid.secret));
      if (p.status !== 200 || !p.data?.binarySecurityToken) return json({ error: "ZATCA did not issue the production certificate", zatca: p, checks }, 400);
      await admin
        .from("zatca_egs")
        .update({ pcsid_token: p.data.binarySecurityToken, pcsid_secret: p.data.secret, status: "Connected", connected_at: new Date().toISOString(), icv: 0, pih: FIRST_PIH, updated_at: new Date().toISOString() })
        .eq("company_id", company);
      return json({ ok: true, env, checks });
    }

    /* ---------- send one invoice: clearance (B2B standard) or reporting (B2C simplified) ---------- */
    if (body.action === "submit") {
      const { data: egs } = await admin.from("zatca_egs").select("*").eq("company_id", company).maybeSingle();
      if (!egs?.pcsid_token) return json({ error: "ZATCA is not connected yet. Settings → ZATCA → Connect." }, 400);
      const { data: inv } = await admin.from("invoices").select("*").eq("id", body.invoice_id).eq("company_id", company).maybeSingle();
      if (!inv) return json({ error: "Invoice not found" }, 404);
      if (["CLEARED", "REPORTED"].includes(inv.zatca_status)) return json({ ok: true, already: true, status: inv.zatca_status });
      const { data: client } = inv.client_id ? await admin.from("clients").select("*").eq("id", inv.client_id).maybeSingle() : { data: null };
      const simplified = /simplified/i.test(String(inv.invoice_type || ""));
      const docType = (["388", "381", "383"].includes(inv.doc_type) ? inv.doc_type : "388") as "388" | "381" | "383";

      const problems = missingSeller(s);
      if (!simplified) {
        if (!client) problems.push("client");
        else {
          if (!/^3\d{13}3$/.test(String(client.vat_number || "").trim())) problems.push(`${client.name}: VAT number (15 digits) — or mark the invoice Simplified`);
          if (!client.street || !client.city || !/^\d{4}$/.test(String(client.building_number || "")) || !/^\d{5}$/.test(String(client.postal_code || "")) || !client.district)
            problems.push(`${client.name}: national address (street, 4-digit building no., district, city, 5-digit postal code)`);
        }
      }
      if (docType !== "388" && !inv.ref_invoice) problems.push("the original invoice number this note corrects");
      const items = Array.isArray(inv.items) ? inv.items : [];
      if (!items.length) problems.push("at least one line");
      if (problems.length) return json({ error: "Before sending to ZATCA, add: " + problems.join("; ") }, 400);

      // one invoice at a time per company keeps the counter and hash chain in order
      const now = new Date();
      const { data: lock } = await admin
        .from("zatca_egs")
        .update({ busy_until: new Date(now.getTime() + 60_000).toISOString() })
        .eq("company_id", company)
        .or(`busy_until.is.null,busy_until.lt.${now.toISOString()}`)
        .select("icv, pih")
        .maybeSingle();
      if (!lock) return json({ error: "Another invoice is being sent right now. Try again in a minute." }, 409);

      try {
        const icv = Number(lock.icv) + 1;
        const issued = inv.issued_at ? new Date(inv.issued_at) : now;
        const { date, time } = issueParts(issued);
        const vatRate = Number(s.vat_rate ?? 15);
        const doc: InvoiceInput = {
          number: inv.number,
          uuid: crypto.randomUUID(),
          issueDate: date,
          issueTime: time,
          kind: simplified ? "simplified" : "standard",
          docType,
          refNumber: inv.ref_invoice || undefined,
          reason: inv.note_reason || undefined,
          icv,
          pih: lock.pih,
          seller: seller(s) as any,
          buyer: client
            ? { name: client.name, vat: String(client.vat_number || "").trim() || undefined, crn: client.cr_number || undefined, address: client.street ? { street: client.street, building: client.building_number, district: client.district, city: client.city, postal: client.postal_code } : undefined }
            : undefined,
          supplyDate: inv.supply_date || inv.date || date,
          paymentCode: ({ Cash: "10", Credit: "30", "Bank transfer": "42", Card: "48" } as Record<string, string>)[inv.payment_means] || "30",
          lines: items.map((l: any) => ({ name: String(l.description || "Item").slice(0, 250), qty: Number(l.qty) || 1, price: Number(l.rate) || 0, vatRate })),
        };
        const cert = certOf(egs.pcsid_token);
        const signed = signInvoice(doc, egs.private_key, cert);
        const path = simplified ? "/invoices/reporting/single" : "/invoices/clearance/single";
        const r = await zatca(egs.env, path, { invoiceHash: signed.invoiceHash, uuid: doc.uuid, invoice: b64(utf8(signed.xml)) }, { ...basic(egs.pcsid_token, egs.pcsid_secret), "Clearance-Status": simplified ? "0" : "1" });
        const accepted = r.status === 200 || r.status === 202;
        let xml = signed.xml;
        let qr = signed.qr;
        if (accepted && !simplified && r.data?.clearedInvoice) {
          xml = new TextDecoder().decode(unb64(r.data.clearedInvoice));
          const m = xml.match(/<cbc:ID>QR<\/cbc:ID>\s*<cac:Attachment>\s*<cbc:EmbeddedDocumentBinaryObject[^>]*>([^<]+)</);
          if (m) qr = m[1];
        }
        const status = accepted ? (simplified ? "REPORTED" : "CLEARED") : r.status === 400 ? "REJECTED" : "ERROR";
        // the chain moves on with every invoice the device signed
        await admin.from("zatca_egs").update({ icv, pih: signed.invoiceHash, busy_until: null, updated_at: new Date().toISOString() }).eq("company_id", company);
        await admin
          .from("invoices")
          .update({
            zatca_status: status,
            zatca_uuid: doc.uuid,
            zatca_icv: icv,
            zatca_hash: signed.invoiceHash,
            zatca_qr: accepted ? qr : null,
            zatca_xml: xml,
            zatca_result: { http: r.status, env: egs.env, ...(r.data || {}), clearedInvoice: undefined },
            zatca_sent_at: new Date().toISOString(),
          })
          .eq("id", inv.id);
        return json({
          ok: accepted,
          status,
          warnings: r.data?.validationResults?.warningMessages ?? [],
          errors: r.data?.validationResults?.errorMessages ?? (accepted ? [] : [r.data]),
        });
      } catch (e) {
        await admin.from("zatca_egs").update({ busy_until: null }).eq("company_id", company);
        throw e;
      }
    }

    return json({ error: "Unknown action" }, 400);
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
});
