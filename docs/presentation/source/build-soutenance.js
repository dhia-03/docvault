// Builds docs/presentation/DocVault-soutenance.pptx, the final defence deck.
//
// Run from the repository root, with pptxgenjs installed somewhere on NODE_PATH:
//   NODE_PATH=/path/to/node_modules node docs/presentation/source/build-soutenance.js
// Every figure on the slides comes from the docs (vulnerability register,
// progress file, runtime detection, drill record). Speaker notes hold the talk.

const path = require("path");
const pptxgen = require("pptxgenjs");

const OUT = path.join(__dirname, "..", "DocVault-soutenance.pptx");
const FIGURE = path.join(__dirname, "..", "..", "diagrams", "architecture.png");

// Palette taken from the architecture figure: deep navy, teal for what is
// secured, red for what fails.
const THEME = {
  name: "DocVault",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "1B2333", lt1: "FFFFFF", dk2: "13213C", lt2: "EEF2F7",
    accent1: "1F9E86", accent2: "D64545", accent3: "E0A030", accent4: "3B6EA8",
    accent5: "6B7A90", accent6: "8E5BB5", hlink: "1F9E86", folHlink: "6B7A90",
  },
};

const pres = new pptxgen();
pres.layout = "LAYOUT_16x9"; // 10 x 5.625 in
pres.title = "DocVault : soutenance du projet DevSecOps";
pres.author = "Équipe DocVault";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

const NAVY = C.text2, TEXT = C.text1, WHITE = C.background1, MIST = C.background2;
const TEAL = C.accent1, RED = C.accent2, AMBER = C.accent3, SLATE = C.accent5;

// Layouts.
pres.defineSlideMaster({
  title: "TITRE",
  background: { color: NAVY },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 1.25, w: 8.8, h: 0.95, fontSize: 48, bold: true, color: WHITE, valign: "bottom", margin: 0 }, text: "" } },
    { placeholder: { options: { name: "body", type: "body", x: 0.6, y: 2.3, w: 8.8, h: 0.9, fontSize: 20, color: MIST, valign: "top", margin: 0 }, text: "" } },
  ],
});
pres.defineSlideMaster({
  title: "CONTENU",
  background: { color: WHITE },
  margin: [0.5, 0.5, 0.45, 0.5],
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.28, w: 9.0, h: 0.62, fontSize: 30, bold: true, color: NAVY, valign: "middle", margin: 0 }, text: "" } },
    { text: { text: "DocVault · projet DevSecOps · TEK-UP ING-5-SSIR", options: { x: 0.5, y: 5.25, w: 6.0, h: 0.25, fontSize: 10, color: SLATE, margin: 0 } } },
  ],
  slideNumber: { x: 9.0, y: 5.25, w: 0.5, h: 0.25, fontSize: 10, color: SLATE, align: "right" },
});

const content = (section, title) => {
  const slide = pres.addSlide({ masterName: "CONTENU", sectionTitle: section });
  slide.addText(title, { placeholder: "title" });
  return slide;
};

// Small building blocks.
const card = (slide, name, x, y, w, h, fill = MIST) =>
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.08, fill: { color: fill }, line: { color: fill }, objectName: name });

const disc = (slide, name, x, y, d, fill, label, fontSize = 14) => {
  slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill }, objectName: name });
  slide.addText(label, { x, y, w: d, h: d, isTextBox: true, margin: 0, align: "center", valign: "middle", fontSize, bold: true, color: WHITE, objectName: name + " label" });
};

const text = (slide, name, runs, opts) =>
  slide.addText(runs, { isTextBox: true, margin: 0, valign: "top", color: TEXT, fontSize: 14, objectName: name, ...opts });

// 1. Title.
pres.addSection({ title: "Introduction" });
{
  const s = pres.addSlide({ masterName: "TITRE", sectionTitle: "Introduction" });
  s.addText("DocVault", { placeholder: "title" });
  s.addText("Sécuriser une application de documents confidentiels sur tout son cycle de vie", { placeholder: "body" });
  const stats = [["7", "failles corrigées"], ["7", "contrôles en CI"], ["2", "couches de détection"]];
  stats.forEach(([n, label], i) => {
    const x = 0.6 + i * 2.55;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 3.45, w: 2.3, h: 0.85, rectRadius: 0.08, fill: { color: TEAL }, line: { color: TEAL }, objectName: `stat ${i + 1}` });
    s.addText([{ text: n, options: { fontSize: 28, bold: true, breakLine: true } }, { text: label, options: { fontSize: 13 } }],
      { x: x + 0.15, y: 3.5, w: 2.0, h: 0.75, isTextBox: true, margin: 0, color: WHITE, valign: "middle", objectName: `stat ${i + 1} text` });
  });
  s.addText([
    { text: "Chaima Khaalsi · Sourour Kraiem · Dhia Medhioub · Rania Khalfet", options: { breakLine: true } },
    { text: "TEK-UP · ING-5-SSIR · encadrant : O. Mansouri", options: { color: MIST } },
  ], { x: 0.6, y: 4.6, w: 8.8, h: 0.6, isTextBox: true, margin: 0, fontSize: 13, color: WHITE, objectName: "team" });
  s.addNotes("Présentation de l'équipe et du sujet. DocVault est une application de stockage et de partage de documents confidentiels : FastAPI, PostgreSQL, trois rôles (admin, membre, auditeur). Nous l'avons volontairement rendue vulnérable, puis sécurisée à chaque étape de son cycle de vie, avec une preuve pour chaque résultat. [Ajouter la date de la soutenance sur cette diapositive si le format l'exige.]");
}

// 2. Approach.
{
  const s = content("Introduction", "Casser, sécuriser, prouver");
  const steps = [
    ["1", "Casser", "Une application volontairement vulnérable : 7 failles documentées avant correction, puis exploitées par un script.", RED],
    ["2", "Sécuriser", "Une branche par faille, un conteneur et un déploiement durcis, un pipeline qui bloque.", TEAL],
    ["3", "Prouver", "Une preuve pour chaque résultat : runs CI, rapports ZAP, démos de détection, exercices.", NAVY],
  ];
  steps.forEach(([n, head, body, color], i) => {
    const x = 0.5 + i * 3.05;
    card(s, `step ${n}`, x, 1.15, 2.85, 2.75);
    disc(s, `step ${n} number`, x + 0.25, 1.4, 0.6, color, n, 20);
    text(s, `step ${n} title`, head, { x: x + 0.25, y: 2.15, w: 2.35, h: 0.4, fontSize: 20, bold: true, color: NAVY, fontFace: THEME.headFontFace });
    text(s, `step ${n} body`, body, { x: x + 0.25, y: 2.6, w: 2.35, h: 1.2, fontSize: 14 });
  });
  text(s, "tagline", "Un pipeline vert ne prouve pas qu'une application est sûre : chaque contrôle doit dire ce qu'il prouve.",
    { x: 0.5, y: 4.2, w: 9.0, h: 0.7, fontSize: 16, italic: true, color: NAVY });
  s.addNotes("Notre démarche en trois temps. D'abord casser : nous avons placé sept failles, documentées dans le registre avant toute correction, et un script les exploite toutes en local. Ensuite sécuriser : chaque faille a sa branche et sa pull request, le conteneur et Kubernetes sont durcis, et la CI bloque. Enfin prouver : chaque affirmation de ce rapport renvoie à un run CI, un rapport ou une démonstration. La phrase du bas est le fil rouge de la soutenance.");
}

// 3. Requirements.
pres.addSection({ title: "Exigences et architecture" });
{
  const s = content("Exigences et architecture", "Le socle : huit exigences démontrées");
  const items = [
    ["Application vulnérable", "7 failles, registre écrit avant correction"],
    ["Conteneur durci", "UID 10001, 0 CVE système"],
    ["CI bloquante", "5 contrôles exigés, plus ZAP et tests"],
    ["Gestion des secrets", "Révoquer puis purger, démontré"],
    ["Kubernetes durci", "Kyverno refuse un pod root"],
    ["DAST authentifié", "F02, F03, F04 confirmées"],
    ["Détection à l'exécution", "DV-A1 à A4, DV-R1 à R4"],
    ["Réponse aux incidents", "7 playbooks, 2 exercices"],
  ];
  items.forEach(([head, body], i) => {
    const col = i % 4, row = Math.floor(i / 4);
    const x = 0.5 + col * 2.3, y = 1.1 + row * 2.0;
    card(s, `requirement ${i + 1}`, x, y, 2.1, 1.8);
    disc(s, `requirement ${i + 1} check`, x + 0.2, y + 0.2, 0.45, TEAL, String(i + 1), 14);
    text(s, `requirement ${i + 1} title`, head, { x: x + 0.2, y: y + 0.75, w: 1.75, h: 0.5, fontSize: 15, bold: true, color: NAVY });
    text(s, `requirement ${i + 1} proof`, body, { x: x + 0.2, y: y + 1.25, w: 1.75, h: 0.5, fontSize: 12, color: SLATE });
  });
  s.addNotes("Le cahier des charges fixe huit exigences, qui suffisent pour viser vingt sur vingt, à condition d'être démontrées. Les huit sont faites, et le rapport commence par un tableau de conformité qui renvoie chaque exigence à sa preuve. Nous allons les parcourir dans cet ordre.");
}

// 4. Architecture.
{
  const s = content("Exigences et architecture", "Architecture réalisée");
  s.addImage({ path: FIGURE, x: 1.3, y: 0.98, w: 7.4, h: 4.1625, altText: "Architecture de DocVault : dépôt GitHub, étape de sécurité bloquante, cluster kind avec Kyverno et réseau en refus par défaut, ZAP, détection et plan de réponse", objectName: "architecture figure" });
  s.addNotes("Le code part de GitHub vers une étape de sécurité bloquante à cinq contrôles. En cas d'échec, la fusion est refusée. L'application est déployée dans un cluster kind jetable, où Kyverno rejette toute charge non durcie et où le réseau est fermé par défaut. ZAP attaque l'application déployée, et deux couches de détection, les alertes applicatives et Falco, déclenchent le plan de réponse. Précision : le déploiement de test n'attend pas les contrôles statiques, sinon ZAP ne pourrait jamais scanner la version vulnérable ; c'est la fusion dans main qui exige tous les contrôles.");
}

// 5. Threats.
{
  const s = content("Exigences et architecture", "Ce qui peut mal tourner");
  const stats = [["18", "menaces analysées avec STRIDE"], ["6", "actifs, dont les documents et les secrets"], ["10", "catégories OWASP 2025 rattachées aux menaces"]];
  stats.forEach(([n, label], i) => {
    const y = 1.1 + i * 1.3;
    text(s, `threat stat ${i + 1}`, n, { x: 0.5, y, w: 1.2, h: 1.0, fontSize: 48, bold: true, color: TEAL, valign: "middle" });
    text(s, `threat stat ${i + 1} label`, label, { x: 1.75, y: y + 0.2, w: 2.6, h: 0.6, fontSize: 14, valign: "middle" });
  });
  card(s, "main risk", 4.7, 1.1, 4.8, 3.8);
  text(s, "main risk text", [
    { text: "Risque principal", options: { bold: true, fontSize: 18, color: NAVY, breakLine: true } },
    { text: "Un accès non autorisé à des documents confidentiels.", options: { fontSize: 15, breakLine: true } },
    { text: " ", options: { fontSize: 8, breakLine: true } },
    { text: "D'où l'attention portée à :", options: { bold: true, fontSize: 14, breakLine: true } },
    { text: "le contrôle d'accès à chaque document", options: { bullet: true, fontSize: 14, breakLine: true } },
    { text: "la manipulation des fichiers téléversés", options: { bullet: true, fontSize: 14, breakLine: true } },
    { text: "la protection des secrets et des sessions", options: { bullet: true, fontSize: 14, breakLine: true } },
    { text: "le confinement du conteneur", options: { bullet: true, fontSize: 14 } },
  ], { x: 4.95, y: 1.3, w: 4.35, h: 3.45, paraSpaceAfter: 4 });
  s.addNotes("Avant d'écrire le code, nous avons fait un modèle de menaces STRIDE : dix-huit menaces sur six actifs, rattachées à l'OWASP Top 10 2025. Le risque principal est l'accès non autorisé aux documents, ce qui explique où nous avons mis le plus d'effort : contrôle d'accès, fichiers, secrets et confinement.");
}

// 6. The seven flaws.
pres.addSection({ title: "Casser" });
{
  const s = content("Casser", "Sept failles, toutes exploitées");
  const head = (t) => ({ text: t, options: { bold: true, color: WHITE, fill: { color: NAVY } } });
  const rows = [
    [head("ID"), head("Faille"), head("OWASP 2025"), head("Preuve d'exploitation")],
    ["F01", "Accès à tout document par son identifiant", "A01 Contrôle d'accès", "Bob télécharge le document d'Alice"],
    ["F02", "Injection SQL dans la recherche", "A05 Injection", "Empreintes de mots de passe affichées"],
    ["F03", "XSS réfléchi et stocké", "A05 Injection", "Script exécuté dans la page"],
    ["F04", "Traversée de répertoire", "A01 Contrôle d'accès", "Lecture de /etc/passwd"],
    ["F05", "Clé de signature dans le code", "A07 Authentification", "Session admin forgée"],
    ["F06", "PyYAML vulnérable", "A03 Chaîne d'approvisionnement", "Code exécuté dans l'application"],
    ["F07", "Conteneur exécuté en root", "A02 Mauvaise configuration", "Processus en UID 0"],
  ];
  s.addTable(rows, { x: 0.5, y: 1.05, w: 9.0, colW: [0.6, 3.1, 2.5, 2.8], fontSize: 12, color: TEXT, fontFace: THEME.bodyFontFace, border: { type: "solid", pt: 0.5, color: "D5DCE6" }, rowH: 0.36, valign: "middle", objectName: "flaws table" });
  text(s, "flaws note", "Le registre a été écrit avant toute correction. Le script d'exploitation refuse toute cible autre que la machine locale.",
    { x: 0.5, y: 4.55, w: 9.0, h: 0.5, fontSize: 13, italic: true, color: SLATE });
  s.addNotes("Sept failles couvrant cinq catégories de l'OWASP. Chacune a une preuve d'exploitation : par exemple, Bob télécharge un document privé d'Alice simplement en changeant l'identifiant dans l'URL, c'est F01. Le registre a été écrit avant toute correction, comme l'exige le cahier des charges ; on peut le vérifier dans l'historique Git avec le tag v0-vulnerable. Le script d'exploitation run_all.py les rejoue toutes, et il refuse toute cible autre que localhost.");
}

// 7. Blocking pipeline.
pres.addSection({ title: "Sécuriser" });
{
  const s = content("Sécuriser", "Le pipeline bloque, puis laisse passer");
  const cols = [
    ["Version vulnérable (PR #2)", RED, [["Secrets (Gitleaks)", "F05"], ["Code (Semgrep)", "F02, F07"], ["Dépendances (Trivy)", "F06"], ["Image (Trivy)", "189 CVE + F06"], ["Kubernetes (Checkov)", "41 échecs"]], "✗"],
    ["Version corrigée (main)", TEAL, [["Les 5 contrôles exigés", "réussis"], ["DAST (ZAP)", "0 alerte High"], ["Tests (pytest)", "réussis"], ["Fusion dans main", "autorisée"]], "✓"],
  ];
  cols.forEach(([head, color, items, mark], c) => {
    const x = 0.5 + c * 4.6;
    card(s, `pipeline column ${c + 1}`, x, 1.1, 4.4, 3.45);
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.1, w: 4.4, h: 0.6, rectRadius: 0.08, fill: { color }, line: { color }, objectName: `pipeline header ${c + 1}` });
    text(s, `pipeline header ${c + 1} text`, head, { x: x + 0.25, y: 1.1, w: 3.9, h: 0.6, fontSize: 16, bold: true, color: WHITE, valign: "middle" });
    items.forEach(([check, detail], i) => {
      const y = 1.9 + i * 0.5;
      disc(s, `pipeline ${c + 1} mark ${i + 1}`, x + 0.25, y + 0.05, 0.32, color, mark, 12);
      text(s, `pipeline ${c + 1} item ${i + 1}`, [{ text: check, options: { bold: true } }, { text: " · " + detail, options: { color: SLATE } }],
        { x: x + 0.7, y, w: 3.55, h: 0.42, fontSize: 14, valign: "middle" });
    });
  });
  text(s, "protection", "main exige les sept contrôles et une pull request, administrateurs compris.",
    { x: 0.5, y: 4.7, w: 9.0, h: 0.4, fontSize: 14, italic: true, color: NAVY });
  s.addNotes("Les cinq contrôles exigés tournent en CI depuis des images épinglées par empreinte, avec des seuils écrits et justifiés dans la politique de sécurité : par exemple, tout secret bloque, alors que Trivy ne bloque que sur High ou Critical avec un correctif disponible. La version vulnérable échoue aux cinq, et ces échecs sont gardés comme preuve sur la PR 2. La version corrigée passe les sept contrôles, et main ne peut recevoir qu'une pull request qui les passe tous, même pour un administrateur.");
}

// 8. What each tool sees.
{
  const s = content("Sécuriser", "Chaque outil voit autre chose");
  const flaws = ["F01", "F02", "F03", "F04", "F05", "F06", "F07"];
  const tools = [
    ["Gitleaks", ["F05"]], ["Semgrep", ["F02", "F07"]], ["Trivy", ["F06"]], ["Checkov", ["F07"]],
    ["ZAP", ["F02", "F03", "F04"]], ["Tests pytest", ["F01"]],
  ];
  const x0 = 0.5, y0 = 1.1, labelW = 1.55, cellW = 0.62, cellH = 0.48;
  flaws.forEach((f, j) => text(s, `matrix head ${f}`, f, { x: x0 + labelW + j * cellW, y: y0, w: cellW, h: 0.4, fontSize: 13, bold: true, align: "center", color: NAVY }));
  tools.forEach(([tool, found], i) => {
    const y = y0 + 0.45 + i * cellH;
    text(s, `matrix row ${tool}`, tool, { x: x0, y, w: labelW, h: cellH, fontSize: 14, bold: true, valign: "middle" });
    flaws.forEach((f, j) => {
      const hit = found.includes(f);
      const color = hit ? (tool === "ZAP" ? AMBER : tool === "Tests pytest" ? RED : TEAL) : MIST;
      s.addShape(pres.shapes.OVAL, { x: x0 + labelW + j * cellW + 0.17, y: y + 0.1, w: 0.28, h: 0.28, fill: { color }, line: { color }, objectName: `matrix ${tool} ${f}` });
    });
  });
  const calls = [["4 / 7", "trouvées par les outils statiques", TEAL], ["+ 2", "par ZAP : F03 et F04", AMBER], ["F01", "seuls les tests, avec deux utilisateurs", RED]];
  calls.forEach(([big, label, color], i) => {
    const y = 1.1 + i * 1.25;
    card(s, `finding ${i + 1}`, 6.55, y, 2.95, 1.1);
    text(s, `finding ${i + 1} number`, big, { x: 6.75, y: y + 0.1, w: 2.6, h: 0.5, fontSize: 26, bold: true, color });
    text(s, `finding ${i + 1} label`, label, { x: 6.75, y: y + 0.58, w: 2.6, h: 0.47, fontSize: 13 });
  });
  s.addNotes("C'est notre principal constat. Les outils statiques, Gitleaks, Semgrep, Trivy et Checkov, trouvent quatre failles sur sept. ZAP en ajoute deux, la XSS et la traversée de répertoire, que Semgrep avait manquées. Et F01, l'accès à un document par son identifiant, aucun scanner ne la voit : c'est une faille de logique métier. Seule une suite de tests qui se connecte avec deux utilisateurs la détecte. C'est pour cela que la suite pytest est devenue un contrôle requis.");
}

// 9. Hardening.
{
  const s = content("Sécuriser", "Conteneur et Kubernetes durcis");
  const stats = [["189 → 0", "CVE système dans l'image"], ["1,19 Go → 230 Mo", "taille de l'image"], ["UID 0 → 10001", "utilisateur du processus"], ["41 → 0", "échecs Checkov"]];
  stats.forEach(([big, label], i) => {
    const col = i % 2, row = Math.floor(i / 2);
    const x = 0.5 + col * 3.05, y = 1.1 + row * 1.75;
    card(s, `hardening stat ${i + 1}`, x, y, 2.85, 1.55);
    text(s, `hardening stat ${i + 1} number`, big, { x: x + 0.2, y: y + 0.25, w: 2.5, h: 0.6, fontSize: 20, bold: true, color: TEAL });
    text(s, `hardening stat ${i + 1} label`, label, { x: x + 0.2, y: y + 0.9, w: 2.5, h: 0.45, fontSize: 14 });
  });
  card(s, "kubernetes", 6.7, 1.1, 2.8, 3.3, NAVY);
  text(s, "kubernetes text", [
    { text: "Dans le cluster", options: { bold: true, fontSize: 16, breakLine: true } },
    { text: "lecture seule, sans capacités", options: { bullet: true, breakLine: true } },
    { text: "pas de jeton de service", options: { bullet: true, breakLine: true } },
    { text: "réseau en refus par défaut", options: { bullet: true, breakLine: true } },
    { text: "Kyverno refuse un pod root : 4 politiques", options: { bullet: true } },
  ], { x: 6.9, y: 1.3, w: 2.45, h: 3.0, fontSize: 14, color: WHITE, paraSpaceAfter: 6 });
  text(s, "exceptions", "Deux exceptions Checkov documentées (E1, E2), dues à l'absence de registre d'images.",
    { x: 0.5, y: 4.65, w: 9.0, h: 0.4, fontSize: 13, italic: true, color: SLATE });
  s.addNotes("Pour F07, le conteneur tournait en root sur une image complète. L'image est maintenant en deux étapes, sur une base slim épinglée par empreinte, avec un utilisateur dédié. Résultat : zéro vulnérabilité système au lieu de 189, et une image cinq fois plus petite. Dans Kubernetes, chaque pod est non root, en lecture seule, sans capacités ni jeton, et le réseau est fermé par défaut. Kyverno le garantit : à chaque déploiement, nous lui soumettons un pod sans contexte de sécurité, et les quatre politiques le refusent. Il reste deux exceptions Checkov, documentées avec un responsable et une échéance, liées à l'absence de registre d'images.");
}

// 10. DAST.
{
  const s = content("Sécuriser", "DAST authentifié avec ZAP");
  const steps = ["Déploiement sur un cluster kind jetable", "Connexion en tant qu'alice, jeton CSRF compris", "Exploration puis scan actif", "Échec si une alerte High apparaît"];
  steps.forEach((step, i) => {
    const y = 1.15 + i * 0.85;
    disc(s, `dast step ${i + 1}`, 0.5, y, 0.5, NAVY, String(i + 1), 16);
    text(s, `dast step ${i + 1} text`, step, { x: 1.15, y, w: 3.6, h: 0.5, fontSize: 15, valign: "middle" });
  });
  const results = [["Version vulnérable", "4 alertes High", "F02 injection SQL · F03 XSS · F04 traversée", RED], ["Version finale", "0 High · 0 Medium", "seules restent des alertes informatives", TEAL]];
  results.forEach(([head, big, detail, color], i) => {
    const y = 1.1 + i * 1.8;
    card(s, `dast result ${i + 1}`, 5.1, y, 4.4, 1.6);
    text(s, `dast result ${i + 1} title`, head, { x: 5.35, y: y + 0.15, w: 4.0, h: 0.35, fontSize: 14, bold: true, color: SLATE });
    text(s, `dast result ${i + 1} number`, big, { x: 5.35, y: y + 0.5, w: 4.0, h: 0.55, fontSize: 26, bold: true, color });
    text(s, `dast result ${i + 1} detail`, detail, { x: 5.35, y: y + 1.1, w: 4.0, h: 0.4, fontSize: 13 });
  });
  s.addNotes("ZAP tourne dans le pipeline, après le déploiement, et il est authentifié : il se connecte comme alice, en récupérant le jeton CSRF, et vérifie qu'il reste connecté. Sur la version vulnérable, il lève quatre alertes High qui confirment trois failles : l'injection SQL, la XSS et la traversée de répertoire. Le cahier des charges en demandait au moins deux. Sur la version finale, il n'y a plus aucune alerte High ni Medium. Nous avons aussi traité un faux positif : une alerte de traversée sans preuve, écartée après analyse.");
}

// 11. Revoke then purge.
{
  const s = content("Sécuriser", "Révoquer d'abord, purger ensuite");
  const steps = [
    ["Révoquer", "La clé sort du code : fournie à l'exécution, différente par environnement"],
    ["Vérifier", "Une session forgée avec l'ancienne clé est refusée (HTTP 303)"],
    ["Purger", "9 branches et le tag réécrits ; main intacte"],
    ["Vérifier", "Clone neuf : 0 occurrence, Gitleaks au vert"],
  ];
  steps.forEach(([head, body], i) => {
    const x = 0.5 + i * 2.3;
    card(s, `secret step ${i + 1}`, x, 1.15, 2.1, 2.6);
    disc(s, `secret step ${i + 1} number`, x + 0.2, 1.35, 0.5, i % 2 === 0 ? NAVY : TEAL, String(i + 1), 16);
    text(s, `secret step ${i + 1} title`, head, { x: x + 0.2, y: 2.0, w: 1.75, h: 0.4, fontSize: 17, bold: true, color: NAVY });
    text(s, `secret step ${i + 1} body`, body, { x: x + 0.2, y: 2.45, w: 1.75, h: 1.25, fontSize: 13 });
  });
  text(s, "why order", "Pourquoi cet ordre : clones, forks et caches gardent l'ancienne valeur. Seule la révocation la rend inutile.",
    { x: 0.5, y: 4.05, w: 9.0, h: 0.7, fontSize: 15, italic: true, color: NAVY });
  s.addNotes("La faille F05 était une clé de signature écrite dans le code, et le dépôt est public : il faut la considérer comme connue. Nous avons d'abord révoqué : la clé est fournie à l'exécution, et une session forgée avec l'ancienne clé est refusée. Ensuite seulement nous avons purgé l'historique, avec un script qui travaille sur une copie, vérifie le résultat avec Gitleaks, et refuse de réécrire main. Enfin nous avons vérifié dans un clone neuf. L'ordre compte : purger seul ne sert à rien, car toute copie déjà faite garde la clé ; GitHub garde aussi les anciens commits dans les références des pull requests.");
}

// 12. Detection.
pres.addSection({ title: "Détecter et répondre" });
{
  const s = content("Détecter et répondre", "Détecter pendant l'exécution");
  const layers = [
    ["Application", "Événements JSON, champs filtrés", [["DV-A1", "force brute"], ["DV-A2", "session forgée"], ["DV-A3", "sondage de documents"], ["DV-A4", "sondage de privilèges"]], TEAL],
    ["Conteneurs (Falco)", "Appels système, sonde eBPF", [["DV-R1", "shell dans un conteneur"], ["DV-R2", "programme inattendu"], ["DV-R3", "fichiers sensibles"], ["DV-R4", "connexion sortante"]], NAVY],
  ];
  layers.forEach(([head, sub, rules, color], c) => {
    const x = 0.5 + c * 4.6;
    card(s, `layer ${c + 1}`, x, 1.1, 4.4, 3.3);
    text(s, `layer ${c + 1} title`, head, { x: x + 0.25, y: 1.25, w: 3.9, h: 0.4, fontSize: 18, bold: true, color });
    text(s, `layer ${c + 1} subtitle`, sub, { x: x + 0.25, y: 1.65, w: 3.9, h: 0.35, fontSize: 13, color: SLATE });
    rules.forEach(([id, name], i) => {
      const y = 2.15 + i * 0.52;
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: x + 0.25, y, w: 0.85, h: 0.38, rectRadius: 0.06, fill: { color }, line: { color }, objectName: `rule ${id}` });
      text(s, `rule ${id} id`, id, { x: x + 0.25, y, w: 0.85, h: 0.38, fontSize: 12, bold: true, color: WHITE, align: "center", valign: "middle" });
      text(s, `rule ${id} name`, name, { x: x + 1.25, y, w: 2.95, h: 0.38, fontSize: 14, valign: "middle" });
    });
  });
  text(s, "detection proof", "Chaque règle est déclenchée et vérifiée à chaque run CI. Un déploiement normal ne lève aucune alerte.",
    { x: 0.5, y: 4.55, w: 9.0, h: 0.52, fontSize: 14, italic: true, color: NAVY });
  s.addNotes("La détection a deux couches. L'application écrit ses événements de sécurité en JSON, avec une liste blanche de champs pour ne jamais journaliser de mot de passe ou de cookie, et quatre règles en tirent des alertes. Falco surveille les appels système des conteneurs avec quatre règles propres à DocVault. Le point important : à chaque run CI, deux scripts déclenchent chaque règle de façon inoffensive et vérifient qu'elle s'est bien déclenchée. Et le déploiement échoue si un déploiement normal lève la moindre alerte, ce qui nous protège des règles bruyantes.");
}

// 13. Response and drills.
{
  const s = content("Détecter et répondre", "Le plan de réponse, exercé");
  const drills = [
    ["P1 · clé forgée ou volée", "0,15 s", "2,4 s", "un seul utilisateur déconnecté, puis clé changée"],
    ["P2 · conteneur compromis", "0,2 s", "1,4 s", "pod isolé, preuves gardées, secrets changés"],
  ];
  drills.forEach(([head, detect, contain, detail], i) => {
    const y = 1.1 + i * 1.75;
    card(s, `drill ${i + 1}`, 0.5, y, 5.6, 1.55);
    text(s, `drill ${i + 1} title`, head, { x: 0.75, y: y + 0.15, w: 5.1, h: 0.35, fontSize: 16, bold: true, color: NAVY });
    text(s, `drill ${i + 1} detect`, [{ text: detect, options: { fontSize: 24, bold: true, color: TEAL, breakLine: true } }, { text: "pour détecter", options: { fontSize: 12, color: SLATE } }], { x: 0.75, y: y + 0.55, w: 1.4, h: 0.8 });
    text(s, `drill ${i + 1} contain`, [{ text: contain, options: { fontSize: 24, bold: true, color: TEAL, breakLine: true } }, { text: "pour contenir", options: { fontSize: 12, color: SLATE } }], { x: 2.25, y: y + 0.55, w: 1.4, h: 0.8 });
    text(s, `drill ${i + 1} detail`, detail, { x: 3.8, y: y + 0.6, w: 2.1, h: 0.8, fontSize: 13 });
  });
  card(s, "plan", 6.35, 1.1, 3.15, 3.3, NAVY);
  text(s, "plan text", [
    { text: "Le plan", options: { bold: true, fontSize: 16, breakLine: true } },
    { text: "7 playbooks avec commandes réelles", options: { bullet: true, breakLine: true } },
    { text: "sévérités liées à chaque alerte", options: { bullet: true, breakLine: true } },
    { text: "preuves gardées avant d'agir", options: { bullet: true, breakLine: true } },
    { text: "2 corrections issues des exercices", options: { bullet: true } },
  ], { x: 6.55, y: 1.3, w: 2.8, h: 3.0, fontSize: 14, color: WHITE, paraSpaceAfter: 6 });
  text(s, "drill caveat", "Exercices techniques scriptés : ils prouvent les détections et les commandes. Une répétition par l'équipe reste à faire.",
    { x: 0.5, y: 4.6, w: 9.0, h: 0.45, fontSize: 13, italic: true, color: SLATE });
  s.addNotes("Le plan de réponse a sept playbooks, chacun avec des commandes réelles, les preuves à garder avant d'agir, et la vérification finale. Nous l'avons exercé sur deux scénarios. P1 : un cookie forgé est détecté en 0,15 seconde ; un cookie volé est contenu en déconnectant un seul utilisateur, puis nous traitons la clé comme exposée et la changeons. P2 : un shell dans le conteneur est détecté par Falco en 0,2 seconde, et le pod est isolé sans détruire les preuves. Soyons honnêtes sur ces temps : ce sont ceux d'un script, pas d'une équipe. Les exercices ont corrigé deux points du plan, notamment qu'après un redémarrage il faut attendre la fin de l'ancien pod.");
}

// 14. Limits.
pres.addSection({ title: "Conclusion" });
{
  const s = content("Conclusion", "Ce que nos contrôles ne prouvent pas");
  const limits = [
    ["F01 est invisible aux scanners", "Seuls les tests métier la couvrent"],
    ["ZAP scanne avec un seul compte", "Il ne teste pas l'accès entre utilisateurs"],
    ["Pas de HTTPS en local", "Le drapeau Secure du cookie n'y est pas exercé"],
    ["Tests sur SQLite", "Le comportement propre à PostgreSQL relève de ZAP et du script"],
    ["Purge incomplète côté GitHub", "Les références de PR gardent les anciens commits"],
    ["Pas de registre d'images", "D'où les exceptions E1 et E2"],
  ];
  limits.forEach(([head, body], i) => {
    const col = i % 3, row = Math.floor(i / 3);
    const x = 0.5 + col * 3.05, y = 1.1 + row * 1.85;
    card(s, `limit ${i + 1}`, x, y, 2.85, 1.65);
    disc(s, `limit ${i + 1} mark`, x + 0.2, y + 0.2, 0.4, AMBER, "!", 16);
    text(s, `limit ${i + 1} title`, head, { x: x + 0.75, y: y + 0.17, w: 1.95, h: 0.6, fontSize: 14, bold: true, color: NAVY });
    text(s, `limit ${i + 1} body`, body, { x: x + 0.2, y: y + 0.85, w: 2.45, h: 0.7, fontSize: 13 });
  });
  s.addNotes("Le rapport consacre un chapitre entier à ce que nos contrôles ne prouvent pas. Les principaux : F01 n'est visible d'aucun scanner ; ZAP ne teste qu'avec un compte, donc pas l'accès d'un utilisateur aux données d'un autre ; il n'y a pas de HTTPS en local ; les tests tournent sur SQLite ; la purge laisse les anciens commits accessibles par les références de pull request jusqu'à une demande au support GitHub ; et l'absence de registre d'images nous a obligés à deux exceptions Checkov, documentées.");
}

// 15. AI use.
{
  const s = content("Conclusion", "Usage de l'IA, déclaré");
  card(s, "ai tool", 0.5, 1.1, 4.3, 3.4);
  text(s, "ai tool text", [
    { text: "Outil", options: { bold: true, fontSize: 16, color: NAVY, breakLine: true } },
    { text: "Claude Code, modèle Claude Opus 5.5, avec des sous-agents pour certaines parties.", options: { fontSize: 14, breakLine: true } },
    { text: " ", options: { fontSize: 8, breakLine: true } },
    { text: "Utilisé pour", options: { bold: true, fontSize: 16, color: NAVY, breakLine: true } },
    { text: "le code et les scripts", options: { bullet: true, fontSize: 14, breakLine: true } },
    { text: "la CI, Kubernetes, Falco", options: { bullet: true, fontSize: 14, breakLine: true } },
    { text: "la documentation et ce rapport", options: { bullet: true, fontSize: 14 } },
  ], { x: 0.75, y: 1.3, w: 3.85, h: 3.1, paraSpaceAfter: 4 });
  card(s, "ai validation", 5.1, 1.1, 4.4, 3.4, NAVY);
  text(s, "ai validation text", [
    { text: "Comment c'est vérifié", options: { bold: true, fontSize: 16, breakLine: true } },
    { text: "chaque production a une ligne dans ai-usage.md", options: { bullet: true, breakLine: true } },
    { text: "chaque résultat est rejoué : tests, CI, exécution réelle", options: { bullet: true, breakLine: true } },
    { text: "le travail des sous-agents est relu et corrigé", options: { bullet: true, breakLine: true } },
    { text: "chaque membre valide sa colonne du journal", options: { bullet: true } },
  ], { x: 5.35, y: 1.3, w: 3.95, h: 3.1, fontSize: 14, color: WHITE, paraSpaceAfter: 6 });
  s.addNotes("Le cahier des charges demande de déclarer tout usage de l'IA. Nous avons utilisé Claude Code, avec le modèle Claude Opus 5.5, et des sous-agents pour certaines parties comme Falco, le plan de réponse et le premier jet du rapport. Chaque production est déclarée dans ai-usage.md, avec ce qui a été vérifié. Aucun résultat n'est repris sans avoir été rejoué : tests, CI, exécution sur un vrai cluster. [Compléter selon l'usage réel de chaque membre, en cohérence avec les fiches Annexe B.]");
}

// 16. Conclusion.
{
  const s = pres.addSlide({ masterName: "TITRE", sectionTitle: "Conclusion" });
  s.addText("Ce que nous retenons", { placeholder: "title" });
  s.addText([
    { text: "Chaque couche voit des choses différentes : statique, dynamique, tests, exécution.", options: { bullet: true, breakLine: true } },
    { text: "Une preuve par résultat, et un chapitre sur ce qui n'est pas prouvé.", options: { bullet: true, breakLine: true } },
    { text: "Révoquer d'abord : purger seul ne protège de rien.", options: { bullet: true } },
  ], { x: 0.6, y: 2.4, w: 8.8, h: 1.6, isTextBox: true, margin: 0, fontSize: 18, color: WHITE, paraSpaceAfter: 8, valign: "top", objectName: "takeaways" });
  s.addText("Merci. Questions ?", { x: 0.6, y: 4.3, w: 8.8, h: 0.6, isTextBox: true, margin: 0, fontSize: 24, bold: true, color: TEAL, objectName: "questions" });
  s.addNotes("Trois choses à retenir. Chaque couche voit des choses différentes : aucun outil seul n'aurait trouvé les sept failles. Ce qui compte, c'est de pouvoir dire précisément ce que chaque contrôle prouve, et ce qu'il ne prouve pas. Et pour un secret exposé, l'ordre est toujours le même : révoquer d'abord, purger ensuite. Merci, nous répondons à vos questions.");
}

(async () => {
  await pres.writeFile({ fileName: OUT });
  const skill = process.env.PPTX_SKILL_DIR;
  if (skill) {
    const { applyTheme } = require(path.join(skill, "scripts", "apply_theme.js"));
    await applyTheme(OUT, THEME);
  }
  console.log("wrote", OUT);
})();
