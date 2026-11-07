//! Minimal Markdown table builder.
//!
//! Reports end up pasted into tickets, wikis and pull requests, so the
//! tables have to survive other people's Markdown renderers: every cell is
//! escaped, every row is padded to the header's column count, and a cell
//! value can never break the table by containing `|` or a newline.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
    Center,
}

impl Align {
    fn marker(&self) -> &'static str {
        match self {
            Align::Left => ":---",
            Align::Right => "---:",
            Align::Center => ":---:",
        }
    }
}

/// Escape a cell so it cannot terminate the row or open a new block.
pub fn escape_cell(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("<br>"),
            '\r' => {}
            '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct Table {
    headers: Vec<String>,
    align: Vec<Align>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new<I, S>(headers: I) -> Table
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let headers: Vec<String> = headers.into_iter().map(Into::into).collect();
        let align = vec![Align::Left; headers.len()];
        Table { headers, align, rows: Vec::new() }
    }

    pub fn align(mut self, column: usize, align: Align) -> Table {
        if let Some(slot) = self.align.get_mut(column) {
            *slot = align;
        }
        self
    }

    /// Add a row. Extra cells are dropped, missing cells are rendered empty,
    /// so a malformed report degrades instead of producing broken Markdown.
    pub fn row<I, S>(&mut self, cells: I) -> &mut Table
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let width = self.headers.len();
        let mut row: Vec<String> = cells.into_iter().map(|c| escape_cell(c.as_ref())).collect();
        row.truncate(width);
        while row.len() < width {
            row.push(String::new());
        }
        self.rows.push(row);
        self
    }

    pub fn len(&self) -> usize { self.rows.len() }
    pub fn is_empty(&self) -> bool { self.rows.is_empty() }

    pub fn render(&self) -> String {
        if self.headers.is_empty() { return String::new(); }
        let mut out = String::new();
        out.push('|');
        for h in &self.headers {
            out.push(' ');
            out.push_str(&escape_cell(h));
            out.push_str(" |");
        }
        out.push('\n');
        out.push('|');
        for a in &self.align {
            out.push(' ');
            out.push_str(a.marker());
            out.push_str(" |");
        }
        out.push('\n');
        for row in &self.rows {
            out.push('|');
            for cell in row {
                out.push(' ');
                out.push_str(cell);
                out.push_str(" |");
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_aligned_table() {
        let mut t = Table::new(["path", "size"]).align(1, Align::Right);
        t.row(["a.exe", "1024"]);
        t.row(["b|c.dll", "2048"]);
        let md = t.render();
        let lines: Vec<&str> = md.lines().collect();
        assert_eq!(lines[0], "| path | size |");
        assert_eq!(lines[1], "| :--- | ---: |");
        assert_eq!(lines[2], "| a.exe | 1024 |");
        assert_eq!(lines[3], "| b\\|c.dll | 2048 |");
        for line in &lines {
            assert_eq!(line.matches(" |").count(), 2, "column count drifted: {line}");
        }
    }

    #[test]
    fn malformed_rows_are_normalized() {
        let mut t = Table::new(["a", "b", "c"]);
        t.row(["only one"]);
        t.row(["1", "2", "3", "4", "5"]);
        let md = t.render();
        assert!(md.contains("| only one |  |  |"));
        assert!(md.contains("| 1 | 2 | 3 |"));
        assert!(!md.contains('4'), "extra cells are dropped:\n{md}");
    }

    #[test]
    fn newlines_and_tabs_never_break_a_row() {
        assert_eq!(escape_cell("a\nb\tc|d"), "a<br>b c\\|d");
        let mut t = Table::new(["x"]);
        t.row(["line1\nline2"]);
        assert_eq!(t.render().lines().count(), 3);
    }

    #[test]
    fn empty_table_renders_nothing() {
        assert_eq!(Table::default().render(), "");
        let mut t = Table::new(["only"]);
        assert!(t.is_empty() && t.len() == 0);
        t.row(["v"]);
        assert_eq!(t.len(), 1);
    }
}
