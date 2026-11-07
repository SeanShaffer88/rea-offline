//! Everything the WizTree-style window displays, with **no windowing code**.
//!
//! The UI is built on two pure data structures — a size tree and a
//! squarified treemap — plus small view/filter state. Keeping them free of
//! any Win32 (or X11) types means they are unit-testable on every platform
//! and in CI, which is where this logic actually gets exercised.
//!
//! Deliberate differences from WizTree, because this tool is not a disk
//! space analyzer (`docs/GUI.md` has the full rationale):
//!   * a node is coloured by **risk, not extension**;
//!   * a node carries its SHA-256, imphash and findings, so the grid can be
//!     sorted by `Risk` where WizTree sorts by `Size`;
//!   * the treemap shows suspicious *files* as red tiles and everything
//!     benign as a muted neutral, so the eye lands on the evidence first.

use crate::json::Value;
use crate::rules::Severity;
use std::collections::BTreeMap;

/// Colour class of a treemap tile / grid row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tint {
    /// No findings above `info`.
    Clean,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Tint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tint::Clean => "clean",
            Tint::Info => "info",
            Tint::Low => "low",
            Tint::Medium => "medium",
            Tint::High => "high",
            Tint::Critical => "critical",
        }
    }

    /// `0xRRGGBB`. Chosen for a dark UI: benign things recede, evidence
    /// advances. Values are also legible on light backgrounds (mid-tone).
    pub fn rgb(&self) -> u32 {
        match self {
            Tint::Clean => 0x4a5568,
            Tint::Info => 0x718096,
            Tint::Low => 0x2f855a,
            Tint::Medium => 0xb7791f,
            Tint::High => 0xc05621,
            Tint::Critical => 0x9b2c2c,
        }
    }

    fn from_severity(severity: Severity) -> Tint {
        match severity {
            Severity::Info => Tint::Info,
            Severity::Low => Tint::Low,
            Severity::Medium => Tint::Medium,
            Severity::High => Tint::High,
            Severity::Critical => Tint::Critical,
        }
    }
}

/// One file's risk-relevant facts, extracted from a report.
#[derive(Debug, Clone, PartialEq)]
pub struct Artifact {
    /// Path relative to the report root, `/`-separated.
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    pub imphash: Option<String>,
    pub format: String,
    pub risk: u64,
    pub tint: Tint,
    /// Rule ids that fired for this file, strongest first.
    pub findings: Vec<(String, String, Severity)>,
}

/// A directory node in the size tree. Sizes are inclusive of children.
#[derive(Debug, Clone, Default)]
pub struct DirNode {
    pub name: String,
    pub size: u64,
    pub file_count: u64,
    /// Worst tint anywhere beneath this node — what a collapsed row shows.
    pub worst: Option<Tint>,
    pub risk: u64,
    pub children: Vec<DirNode>,
    pub files: Vec<Artifact>,
}

impl DirNode {
    fn recompute(&mut self) -> (u64, u64, u64) {
        let mut size = 0u64;
        let mut count = 0u64;
        let mut worst = 0u64; // Tint is Ord; 0 == Clean
        for child in &mut self.children {
            let (child_size, child_count, child_worst) = child.recompute();
            size += child_size;
            count += child_count;
            worst = worst.max(child_worst);
        }
        for file in &self.files {
            size += file.size;
            count += 1;
            worst = worst.max(tint_rank(file.tint));
        }
        self.size = size;
        self.file_count = count;
        self.worst = Tint::from_rank(worst);
        self.risk = self.risk.max(
            self.children.iter().map(|c| c.risk).max().unwrap_or(0),
        );
        self.risk = self.risk.max(self.files.iter().map(|f| f.risk).max().unwrap_or(0));
        // Deterministic display order: biggest first, then name.
        self.children
            .sort_by(|a, b| b.size.cmp(&a.size).then(a.name.cmp(&b.name)));
        self.files
            .sort_by(|a, b| b.size.cmp(&a.size).then(a.path.cmp(&b.path)));
        (size, count, worst)
    }
}

fn tint_rank(tint: Tint) -> u64 {
    match tint {
        Tint::Clean => 0,
        Tint::Info => 1,
        Tint::Low => 2,
        Tint::Medium => 3,
        Tint::High => 4,
        Tint::Critical => 5,
    }
}

impl Tint {
    fn from_rank(rank: u64) -> Option<Tint> {
        match rank {
            0 => None,
            1 => Some(Tint::Info),
            2 => Some(Tint::Low),
            3 => Some(Tint::Medium),
            4 => Some(Tint::High),
            _ => Some(Tint::Critical),
        }
    }
}

/// Flat row as the tree-grid renders it (WizTree shows a tree *and* a grid).
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub depth: usize,
    pub name: String,
    pub path: String,
    pub size: u64,
    pub file_count: u64,
    pub tint: Tint,
    pub risk: u64,
    pub format: String,
    pub sha256: String,
    /// Whether the row is a directory (affects the expander column).
    pub is_dir: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Name,
    Size,
    Risk,
    Files,
    Format,
}

/// Which rectangles the treemap should draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreemapScope {
    /// One tile per file beneath the current node.
    Files,
    /// One tile per immediate child directory (blended worst tint) plus the
    /// node's own files — WizTree's default.
    TopLevel,
}

#[derive(Debug, Clone)]
pub struct View {
    pub sort: SortColumn,
    pub descending: bool,
    pub scope: TreemapScope,
    pub filter: String,
    /// Minimum risk a file must have to be shown (0 = everything).
    pub min_risk: u64,
    pub hide_clean: bool,
    pub expanded: Vec<String>,
    pub selected: Option<String>,
}

impl Default for View {
    fn default() -> Self {
        View {
            sort: SortColumn::Size,
            descending: true,
            scope: TreemapScope::TopLevel,
            filter: String::new(),
            min_risk: 0,
            hide_clean: false,
            expanded: vec!["".to_string()],
            selected: None,
        }
    }
}

/// Rows visible in the grid for `view`, starting from `root`.
///
/// Filters compose: a row survives only if it (or a descendant) passes the
/// text filter *and* the risk floor leaves nothing hidden — directories that
/// would become empty are dropped, which is what makes "hide clean" usable.
pub fn rows(root: &DirNode, view: &View) -> Vec<Row> {
    let needle = view.filter.to_ascii_lowercase();
    let mut out = Vec::new();
    walk(root, "", 0, &needle, view, &mut out);
    sort_rows(out, view.sort, view.descending)
}

fn passes(file: &Artifact, needle: &str, view: &View) -> bool {
    if view.hide_clean && file.tint == Tint::Clean {
        return false;
    }
    if file.risk < view.min_risk {
        return false;
    }
    needle.is_empty() || file.path.to_ascii_lowercase().contains(needle)
}

fn subtree_has_match(node: &DirNode, needle: &str, view: &View) -> bool {
    if node.files.iter().any(|f| passes(f, needle, view)) {
        return true;
    }
    node.children.iter().any(|c| subtree_has_match(c, needle, view))
}

fn walk(node: &DirNode, path: &str, depth: usize, needle: &str, view: &View, out: &mut Vec<Row>) {
    let self_path = if path.is_empty() {
        node.name.clone()
    } else if node.name.is_empty() {
        path.to_string()
    } else {
        format!("{path}/{}", node.name)
    };
    let expanded = view.expanded.iter().any(|e| e == &self_path);
    let matching_files: Vec<&Artifact> = node.files.iter().filter(|f| passes(f, needle, view)).collect();
    let visible_children: Vec<&DirNode> = node
        .children
        .iter()
        .filter(|c| subtree_has_match(c, needle, view))
        .collect();
    // A directory that filters down to nothing disappears entirely (unless it
    // is the root, so the grid never goes blank without explanation).
    if depth > 0 && matching_files.is_empty() && visible_children.is_empty() {
        return;
    }
    out.push(Row {
        depth,
        name: node.name.clone(),
        path: self_path.clone(),
        size: node.size,
        file_count: node.file_count,
        tint: node.worst.unwrap_or(Tint::Clean),
        risk: node.risk,
        format: "folder".to_string(),
        sha256: String::new(),
        is_dir: true,
    });
    if !expanded {
        return;
    }
    for child in visible_children {
        walk(child, &self_path, depth + 1, needle, view, out);
    }
    for file in matching_files {
        out.push(Row {
            depth: depth + 1,
            name: file.path.rsplit('/').next().unwrap_or(&file.path).to_string(),
            path: file.path.clone(),
            size: file.size,
            file_count: 1,
            tint: file.tint,
            risk: file.risk,
            format: file.format.clone(),
            sha256: file.sha256.clone(),
            is_dir: false,
        });
    }
}

/// Sort siblings while keeping child groups under their parent.
///
/// The grid is a tree, so a global sort would scatter files away from the
/// directory they live in. Rows arrive in pre-order, which makes every
/// subtree a contiguous slice — sort those slices, recursively.
fn sort_rows(rows: Vec<Row>, column: SortColumn, descending: bool) -> Vec<Row> {
    if rows.is_empty() {
        return rows;
    }
    let compare = |a: &Row, b: &Row| {
        let ordering = match column {
            SortColumn::Name => a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()),
            SortColumn::Size => a.size.cmp(&b.size),
            SortColumn::Risk => a.risk.cmp(&b.risk),
            SortColumn::Files => a.file_count.cmp(&b.file_count),
            SortColumn::Format => a.format.cmp(&b.format),
        }
        .then(a.name.cmp(&b.name));
        if descending { ordering.reverse() } else { ordering }
    };
    fn span_len(rows: &[Row]) -> usize {
        // rows[0] owns every following row that is deeper than it.
        let depth = rows[0].depth;
        let mut end = 1;
        while end < rows.len() && rows[end].depth > depth {
            end += 1;
        }
        end
    }
    fn sort_block(block: &[Row], compare: &dyn Fn(&Row, &Row) -> std::cmp::Ordering) -> Vec<Row> {
        let mut out = Vec::with_capacity(block.len());
        out.push(block[0].clone());
        let mut groups: Vec<Vec<Row>> = Vec::new();
        let mut index = 1;
        while index < block.len() {
            let length = span_len(&block[index..]);
            groups.push(sort_block(&block[index..index + length], compare));
            index += length;
        }
        groups.sort_by(|a, b| compare(&a[0], &b[0]));
        for group in groups {
            out.extend(group);
        }
        out
    }
    sort_block(&rows, &compare)
}

/// Build the size tree from a report's `report.files` array.
pub fn from_report(report: &Value) -> DirNode {
    let mut root = DirNode { name: String::new(), ..Default::default() };
    // file path → (artifact)
    let mut artifacts: Vec<Artifact> = Vec::new();
    // Findings by file, so each artifact knows why it is coloured.
    let mut findings_by_file: BTreeMap<String, Vec<(String, String, Severity)>> = BTreeMap::new();
    if let Some(rules) = report.get("rules") {
        if let Some(Value::Array(items)) = rules.get("findings") {
            for item in items {
                let file = item.get("file").and_then(Value::as_str).unwrap_or("").to_string();
                let rule = item.get("rule").and_then(Value::as_str).unwrap_or("").to_string();
                let title = item.get("title").and_then(Value::as_str).unwrap_or("").to_string();
                let severity = severity_from(
                    item.get("severity").and_then(Value::as_str).unwrap_or("info"),
                );
                findings_by_file.entry(file).or_default().push((rule, title, severity));
            }
        }
    }
    if let Some(Value::Array(files)) = report.get("files") {
        for file in files {
            let path = file.get("path").and_then(Value::as_str).unwrap_or("").to_string();
            if path.is_empty() {
                continue;
            }
            let size = match file.get("size") {
                Some(Value::Number(x)) if *x > 0.0 => *x as u64,
                _ => 0,
            };
            let mut findings = findings_by_file.remove(&path).unwrap_or_default();
            findings.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
            let worst = findings.iter().map(|f| f.2).max();
            let tint = worst.map(Tint::from_severity).unwrap_or(Tint::Clean);
            artifacts.push(Artifact {
                path,
                size,
                sha256: file.get("sha256").and_then(Value::as_str).unwrap_or("").to_string(),
                md5: file.get("md5").and_then(Value::as_str).unwrap_or("").to_string(),
                imphash: file.get("imphash").and_then(Value::as_str).map(|s| s.to_string()),
                format: file.get("format").and_then(Value::as_str).unwrap_or("").to_string(),
                risk: match file.get("risk") {
                    Some(Value::Number(x)) => *x as u64,
                    _ => tint_score(tint),
                },
                tint,
                findings,
            });
        }
    }
    for artifact in &artifacts {
        insert(&mut root, artifact);
    }
    // Pre-order traversal order is what `sort_rows` relies on to treat each
    // subtree as one contiguous slice.
    root.children.sort_by(|a, b| a.name.cmp(&b.name));
    let _ = root.recompute();
    root
}

fn tint_score(tint: Tint) -> u64 {
    match tint {
        Tint::Clean => 0,
        Tint::Info => 0,
        Tint::Low => 6,
        Tint::Medium => 12,
        Tint::High => 22,
        Tint::Critical => 40,
    }
}

fn severity_from(text: &str) -> Severity {
    match text {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn insert(node: &mut DirNode, artifact: &Artifact) {
    let mut parts: Vec<&str> = artifact.path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 1 {
        node.files.push(artifact.clone());
        return;
    }
    let file_name = parts.pop().unwrap_or_default();
    let mut cursor = node;
    for component in parts {
        let position = match cursor.children.iter().position(|c| c.name == component) {
            Some(index) => index,
            None => {
                cursor.children.push(DirNode { name: component.to_string(), ..Default::default() });
                cursor.children.len() - 1
            }
        };
        cursor = &mut cursor.children[position];
    }
    let mut file = artifact.clone();
    file.path = file_name.to_string();
    cursor.files.push(file);
}

// ---------------------------------------------------------------------------
// Treemap
// ---------------------------------------------------------------------------

/// One drawn rectangle. Coordinates are in the same unit as the layout input
/// (pixels from the UI); `parent` points at the tile that contains it.
#[derive(Debug, Clone, PartialEq)]
pub struct Tile {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    pub label: String,
    pub path: String,
    pub size: u64,
    pub tint: Tint,
    pub risk: u64,
    pub is_dir: bool,
    /// Nesting level: 0 = top-level tile.
    pub depth: usize,
}

/// Squarified treemap of `root`, sized to `width` x `height`.
///
/// Only tiles at least `min_side` pixels wide/tall are emitted (smaller ones
/// are invisible and would just bloat the display list). Each level is laid
/// out inside its parent's rectangle, so hovering a tile can drill down.
pub fn treemap(root: &DirNode, width: f64, height: f64, view: &View, min_side: f64) -> Vec<Tile> {
    let mut out = Vec::new();
    let mut items: Vec<Item> = match view.scope {
        TreemapScope::Files => collect_files(root, &view.filter, view),
        TreemapScope::TopLevel => {
            let mut items: Vec<Item> = root
                .children
                .iter()
                .map(|child| Item {
                    label: child.name.clone(),
                    path: join(&root.name, &child.name),
                    size: child.size.max(1),
                    tint: child.worst.unwrap_or(Tint::Clean),
                    risk: child.risk,
                    is_dir: true,
                    node: Some(child),
                })
                .collect();
            items.extend(root.files.iter().map(|file| Item {
                label: file.path.clone(),
                path: file.path.clone(),
                size: file.size.max(1),
                tint: file.tint,
                risk: file.risk,
                is_dir: false,
                node: None,
            }));
            items
        }
    };
    if view.hide_clean {
        items.retain(|item| item.tint != Tint::Clean);
    }
    if view.min_risk > 0 {
        items.retain(|item| item.risk >= view.min_risk);
    }
    layout_items(&mut items, 0.0, 0.0, width, height, 0, min_side, &mut out);
    out
}

struct Item<'a> {
    label: String,
    path: String,
    size: u64,
    tint: Tint,
    risk: u64,
    is_dir: bool,
    node: Option<&'a DirNode>,
}

fn join(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}/{child}")
    }
}

fn collect_files<'a>(node: &'a DirNode, needle: &str, view: &View) -> Vec<Item<'a>> {
    let mut out = Vec::new();
    for file in &node.files {
        if passes(file, needle, view) {
            out.push(Item {
                label: file.path.clone(),
                path: join(&node.name, &file.path),
                size: file.size.max(1),
                tint: file.tint,
                risk: file.risk,
                is_dir: false,
                node: None,
            });
        }
    }
    for child in &node.children {
        out.extend(collect_files(child, needle, view));
    }
    out
}

fn layout_items<'a>(
    items: &mut Vec<Item<'a>>,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    depth: usize,
    min_side: f64,
    out: &mut Vec<Tile>,
) {
    if items.is_empty() || width <= 0.0 || height <= 0.0 {
        return;
    }
    items.sort_by(|a, b| b.size.cmp(&a.size).then(a.label.cmp(&b.label)));
    let total: u64 = items.iter().map(|i| i.size).sum();
    if total == 0 {
        return;
    }
    let scale = (width * height) / total as f64;
    let areas: Vec<f64> = items.iter().map(|i| i.size as f64 * scale).collect();

    let mut cx = x;
    let mut cy = y;
    let mut cw = width;
    let mut ch = height;
    let mut index = 0usize;
    while index < items.len() {
        let shortest = cw.min(ch);
        if shortest <= 0.0 {
            break;
        }
        // Grow a row while its aspect ratio improves.
        let mut row_end = index + 1;
        let mut best = worst_aspect(&areas[index..row_end], shortest);
        while row_end < items.len() {
            let ratio = worst_aspect(&areas[index..row_end + 1], shortest);
            if ratio > best {
                break;
            }
            best = ratio;
            row_end += 1;
        }
        let row_area: f64 = areas[index..row_end].iter().sum();
        let horizontal = cw >= ch;
        let row_thickness = if shortest > 0.0 { row_area / shortest } else { 0.0 };
        let mut offset2 = 0.0;
        for slot in index..row_end {
            let area = areas[slot];
            let side = if row_thickness > 0.0 { area / row_thickness } else { 0.0 };
            let (tx, ty, tw, th) = if horizontal {
                (cx, cy + offset2, row_thickness, side)
            } else {
                (cx + offset2, cy, side, row_thickness)
            };
            offset2 += side;
            let item = &items[slot];
            if tw >= min_side && th >= min_side {
                out.push(Tile {
                    x: tx,
                    y: ty,
                    w: tw,
                    h: th,
                    label: item.label.clone(),
                    path: item.path.clone(),
                    size: item.size,
                    tint: item.tint,
                    risk: item.risk,
                    is_dir: item.is_dir,
                    depth,
                });
                if let Some(node) = item.node {
                    let mut children: Vec<Item> = node
                        .children
                        .iter()
                        .map(|child| Item {
                            label: child.name.clone(),
                            path: join(&item.path, &child.name),
                            size: child.size.max(1),
                            tint: child.worst.unwrap_or(Tint::Clean),
                            risk: child.risk,
                            is_dir: true,
                            node: Some(child),
                        })
                        .collect();
                    children.extend(node.files.iter().map(|file| Item {
                        label: file.path.clone(),
                        path: join(&item.path, &file.path),
                        size: file.size.max(1),
                        tint: file.tint,
                        risk: file.risk,
                        is_dir: false,
                        node: None,
                    }));
                    // Nested geometry is scaled down so inner tiles are drawn
                    // slightly inset, reading as "inside" the parent.
                    layout_items(
                        &mut children,
                        tx + 1.0,
                        ty + 1.0,
                        (tw - 2.0).max(0.0),
                        (th - 2.0).max(0.0),
                        depth + 1,
                        min_side,
                        out,
                    );
                }
            }
        }
        if horizontal {
            cx += row_thickness;
            cw = (cw - row_thickness).max(0.0);
        } else {
            cy += row_thickness;
            ch = (ch - row_thickness).max(0.0);
        }
        index = row_end;
    }
    let _ = (x, y);
}

/// Worst (largest) aspect ratio of a candidate row. Lower is squarer.
fn worst_aspect(areas: &[f64], shortest: f64) -> f64 {
    if areas.is_empty() || shortest <= 0.0 {
        return f64::INFINITY;
    }
    let total: f64 = areas.iter().sum();
    if total <= 0.0 {
        return f64::INFINITY;
    }
    let thickness = total / shortest;
    let mut worst: f64 = 0.0;
    for area in areas {
        if *area <= 0.0 {
            continue;
        }
        let side = area / thickness;
        let ratio = (thickness / side).max(side / thickness);
        if ratio > worst {
            worst = ratio;
        }
    }
    worst
}

/// Details shown for the selected row: the WizTree "file details" pane,
/// retargeted at evidence.
pub fn details_text(root: &DirNode, path: &str) -> String {
    let Some(artifact) = find_file(root, path) else {
        return format!("{path}\n(no file record)");
    };
    let mut out = String::new();
    out.push_str(&format!("Path:    {path}\n"));
    out.push_str(&format!("Size:    {} bytes\n", artifact.size));
    out.push_str(&format!("Format:  {}\n", artifact.format));
    out.push_str(&format!("Risk:    {} ({})\n", artifact.risk, artifact.tint.as_str()));
    out.push_str(&format!("SHA-256: {}\n", artifact.sha256));
    out.push_str(&format!("MD5:     {}\n", artifact.md5));
    if let Some(imphash) = &artifact.imphash {
        out.push_str(&format!("imphash: {imphash}\n"));
    }
    if artifact.findings.is_empty() {
        out.push_str("Findings: none above info\n");
    } else {
        out.push_str("Findings:\n");
        for (rule, title, severity) in &artifact.findings {
            out.push_str(&format!("  [{}] {rule} — {title}\n", severity.as_str()));
        }
    }
    out
}

fn find_file<'a>(node: &'a DirNode, path: &str) -> Option<&'a Artifact> {
    let mut stack: Vec<(&DirNode, String)> = vec![(node, node.name.clone())];
    while let Some((current, prefix)) = stack.pop() {
        for file in &current.files {
            let full = join(&prefix, &file.path);
            if full == path {
                return Some(file);
            }
        }
        for child in &current.children {
            stack.push((child, join(&prefix, &child.name)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(path: &str, size: u64, tint: Tint, risk: u64) -> Artifact {
        Artifact {
            path: path.to_string(),
            size,
            sha256: "a".repeat(64),
            md5: "b".repeat(32),
            imphash: None,
            format: "PE".to_string(),
            risk,
            tint,
            findings: Vec::new(),
        }
    }

    fn sample_report() -> Value {
        crate::json::parse(
            r#"{
              "files": [
                {"path": "a.dll", "size": 100, "sha256": "aa", "md5": "bb", "format": "PE"},
                {"path": "sub/b.exe", "size": 200, "sha256": "cc", "md5": "dd", "format": "PE", "imphash": "ee"},
                {"path": "sub/deep/c.dat", "size": 300, "sha256": "ff", "md5": "gg", "format": "unknown"},
                {"path": "sub/d_clean.txt", "size": 400, "sha256": "hh", "md5": "ii", "format": "text"}
              ],
              "rules": {
                "findings": [
                  {"rule": "PE100", "title": "W+X section", "severity": "high", "file": "sub/b.exe", "evidence": "x"},
                  {"rule": "PE001", "title": "unsigned", "severity": "low", "file": "a.dll", "evidence": "x"}
                ]
              }
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn tree_aggregates_sizes_and_worst_tint() {
        let tree = from_report(&sample_report());
        assert_eq!(tree.size, 1000);
        assert_eq!(tree.file_count, 4);
        assert_eq!(tree.worst, Some(Tint::High), "worst finding anywhere wins");
        assert_eq!(tree.children.len(), 2, "sub/ and files at root");
        let sub = tree.children.iter().find(|c| c.name == "sub").unwrap();
        assert_eq!(sub.size, 900);
        assert_eq!(sub.file_count, 3);
        assert_eq!(sub.worst, Some(Tint::High));
        // Biggest-first ordering.
        assert_eq!(sub.children[0].name, "deep");
    }

    #[test]
    fn rows_follow_expansion_and_sorting() {
        let tree = from_report(&sample_report());
        let mut view = View::default();
        view.expanded = vec![String::new()];
        let collapsed = rows(&tree, &view);
        // Root + its immediate children/files only.
        assert!(collapsed.iter().all(|r| r.depth <= 1), "{collapsed:?}");

        view.expanded = vec![String::new(), "sub".to_string()];
        let expanded = rows(&tree, &view);
        assert!(expanded.iter().any(|r| r.path == "sub/b.exe"), "{expanded:?}");

        view.sort = SortColumn::Name;
        view.descending = false;
        let by_name = rows(&tree, &view);
        let names: Vec<&str> = by_name.iter().filter(|r| r.depth == 1).map(|r| r.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "ascending name order");
    }

    #[test]
    fn filters_hide_clean_files_and_empty_folders() {
        let tree = from_report(&sample_report());
        let mut view = View::default();
        view.expanded = vec![String::new(), "sub".to_string(), "sub/deep".to_string()];
        view.hide_clean = true;
        let visible = rows(&tree, &view);
        let paths: Vec<&str> = visible.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"sub/b.exe"));
        assert!(!paths.contains(&"sub/d_clean.txt"), "clean file hidden: {paths:?}");
        assert!(!paths.contains(&"sub/deep/c.dat"));
        assert!(!paths.contains(&"sub/deep"), "folder with nothing left disappears");

        view.filter = "clean".to_string();
        view.hide_clean = false;
        let filtered = rows(&tree, &view);
        let paths: Vec<&str> = filtered.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"sub/d_clean.txt"));
        assert!(!paths.contains(&"sub/b.exe"));
    }

    #[test]
    fn treemap_tiles_cover_the_area_without_overlap() {
        let tree = from_report(&sample_report());
        let view = View::default();
        let tiles = treemap(&tree, 800.0, 600.0, &view, 2.0);
        let top: Vec<&Tile> = tiles.iter().filter(|t| t.depth == 0).collect();
        assert!(!top.is_empty());
        let area: f64 = top.iter().map(|t| t.w * t.h).sum();
        // Sum of a squarified layout equals the canvas (rounding aside).
        assert!((area - 800.0 * 600.0).abs() < 1.0, "covered {area}");
        for tile in &top {
            assert!(tile.x >= -0.01 && tile.y >= -0.01);
            assert!(tile.x + tile.w <= 800.01 && tile.y + tile.h <= 600.01);
            assert!(tile.w >= 2.0 && tile.h >= 2.0);
        }
        // No two top-level tiles may overlap.
        for i in 0..top.len() {
            for j in (i + 1)..top.len() {
                let a = top[i];
                let b = top[j];
                let overlap = a.x < b.x + b.w - 0.5
                    && b.x < a.x + a.w - 0.5
                    && a.y < b.y + b.h - 0.5
                    && b.y < a.y + a.h - 0.5;
                assert!(!overlap, "tiles overlap: {a:?} {b:?}");
            }
        }
    }

    #[test]
    fn treemap_nests_children_inside_parents() {
        let tree = from_report(&sample_report());
        let view = View::default();
        let tiles = treemap(&tree, 500.0, 500.0, &view, 4.0);
        let sub = tiles.iter().find(|t| t.path == "sub" && t.depth == 0);
        if let Some(sub) = sub {
            for child in tiles.iter().filter(|t| t.depth == 1 && t.path.starts_with("sub/")) {
                assert!(child.x >= sub.x - 0.01 && child.y >= sub.y - 0.01);
                assert!(child.x + child.w <= sub.x + sub.w + 0.01);
                assert!(child.y + child.h <= sub.y + sub.h + 0.01);
            }
        }
    }

    #[test]
    fn detail_pane_shows_evidence() {
        let tree = from_report(&sample_report());
        let text = details_text(&tree, "sub/b.exe");
        assert!(text.contains("SHA-256: cc"), "{text}");
        assert!(text.contains("PE100"), "{text}");
        assert!(text.contains("high"), "{text}");
        assert!(details_text(&tree, "nope.bin").contains("no file record"));
    }

    #[test]
    fn tint_colours_are_distinct_and_readable() {
        let tints = [Tint::Clean, Tint::Info, Tint::Low, Tint::Medium, Tint::High, Tint::Critical];
        let colours: Vec<u32> = tints.iter().map(|t| t.rgb()).collect();
        let mut unique = colours.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), tints.len());
        for colour in colours {
            // Mid-tone: not so bright it glares, not so dark it vanishes.
            let luma = 0.2126 * ((colour >> 16) & 0xff) as f64
                + 0.7152 * ((colour >> 8) & 0xff) as f64
                + 0.0722 * (colour & 0xff) as f64;
            assert!((32.0..=200.0).contains(&luma), "{colour:#08x} luma {luma}");
        }
    }

    #[test]
    fn empty_report_produces_empty_but_valid_view() {
        let tree = from_report(&Value::Null);
        assert_eq!(tree.size, 0);
        assert!(rows(&tree, &View::default()).len() <= 1);
        assert!(treemap(&tree, 100.0, 100.0, &View::default(), 1.0).is_empty());
    }
}
