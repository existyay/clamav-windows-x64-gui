//! Paper-inspired visual language for the ClamAV GUI.
//!
//! The whole application is built out of three primitive surfaces:
//!
//! * **paper** – the page everything is printed on,
//! * **sunken** – a recessed strip used by the navigation rail,
//! * **card** – a raised sheet that holds a group of controls.
//!
//! On top of that sit a hairline "rule" colour (the printed line), warm ink
//! tones for text, and a single jade accent. Dark mode is not a grey theme but
//! an "ink board": warm charcoal paper with brighter ink.
//!
//! Everything here is `const`/pure so widgets can grab a [`Palette`] without
//! touching the egui context and without allocating.

use egui::{Color32, CornerRadius, FontId, RichText, Stroke, Style, TextStyle, Vec2};

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------

/// A complete colour set for one appearance mode.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub dark: bool,

    /// Page background – the sheet of paper.
    pub paper: Color32,
    /// Recessed surface, used by the navigation rail and log wells.
    pub sunken: Color32,
    /// Raised card surface.
    pub card: Color32,
    /// Alternate card surface for list rows and table headers.
    pub card_alt: Color32,
    /// Colour of a card that is being hovered / selected.
    pub card_hover: Color32,

    /// Primary text ("ink").
    pub ink: Color32,
    /// Secondary text, used for labels and hints.
    pub ink_soft: Color32,
    /// Tertiary text, used for the faintest meta information.
    pub ink_faint: Color32,

    /// Hairline separator / border.
    pub rule: Color32,
    /// A slightly darker hairline, for interactive outlines.
    pub rule_strong: Color32,

    /// Primary accent (jade ink).
    pub accent: Color32,
    /// Pressed / hovered accent.
    pub accent_strong: Color32,
    /// Very light accent wash used for selected rows and badges.
    pub accent_soft: Color32,
    /// Text drawn on top of `accent`.
    pub on_accent: Color32,

    pub success: Color32,
    pub success_surface: Color32,
    pub warning: Color32,
    pub warning_surface: Color32,
    pub danger: Color32,
    pub danger_surface: Color32,
    pub info_surface: Color32,

    /// Alpha used when stamping the paper grain onto `paper`.
    pub grain_alpha: u8,
    /// Tint used for the paper grain (premultiplied).
    pub grain_tint: Color32,
}

macro_rules! rgb {
    ($r:expr, $g:expr, $b:expr) => {
        Color32::from_rgb($r, $g, $b)
    };
}

/// Warm off-white paper with jade ink.
///
/// The contrast ratios between each ink step and the two text surfaces are
/// enforced by a test at the bottom of this file, so a future tweak cannot
/// quietly make hint text unreadable.
pub const LIGHT: Palette = Palette {
    dark: false,

    paper: rgb!(0xF7, 0xF3, 0xEA),
    sunken: rgb!(0xEF, 0xEA, 0xDD),
    card: rgb!(0xFF, 0xFD, 0xF7),
    card_alt: rgb!(0xFA, 0xF6, 0xEC),
    card_hover: rgb!(0xF3, 0xEE, 0xE1),

    ink: rgb!(0x2A, 0x26, 0x21),
    ink_soft: rgb!(0x6C, 0x62, 0x55),
    // Was #9B9082, which measured only 2.83:1 against the paper — below even the
    // 3:1 UI minimum, on text that is set at 11.5px.
    ink_faint: rgb!(0x80, 0x75, 0x67),

    rule: rgb!(0xE1, 0xD8, 0xC6),
    rule_strong: rgb!(0xCC, 0xC0, 0xA8),

    accent: rgb!(0x1E, 0x6B, 0x5A),
    accent_strong: rgb!(0x17, 0x55, 0x47),
    accent_soft: rgb!(0xDD, 0xEB, 0xE4),
    on_accent: rgb!(0xFD, 0xFC, 0xF8),

    success: rgb!(0x36, 0x74, 0x4A),
    success_surface: rgb!(0xE4, 0xF0, 0xE6),
    // Was #9C6B14 (4.19:1) — just under the 4.5:1 needed for status text.
    warning: rgb!(0x91, 0x62, 0x12),
    warning_surface: rgb!(0xFA, 0xEF, 0xD9),
    danger: rgb!(0xA3, 0x36, 0x2C),
    danger_surface: rgb!(0xF9, 0xE6, 0xE3),
    info_surface: rgb!(0xE9, 0xEE, 0xF1),

    grain_alpha: 26,
    grain_tint: Color32::from_rgba_premultiplied(0x00, 0x00, 0x00, 26),
};

/// Warm charcoal "ink board" for dark mode.
pub const DARK: Palette = Palette {
    dark: true,

    paper: rgb!(0x1A, 0x18, 0x15),
    sunken: rgb!(0x13, 0x12, 0x10),
    card: rgb!(0x24, 0x21, 0x1C),
    card_alt: rgb!(0x1F, 0x1D, 0x18),
    card_hover: rgb!(0x2C, 0x28, 0x22),

    ink: rgb!(0xEE, 0xE8, 0xDA),
    ink_soft: rgb!(0xA9, 0x9E, 0x8C),
    // Was #796F61 (3.59:1 against the ink board).
    ink_faint: rgb!(0x8A, 0x7F, 0x70),

    rule: rgb!(0x36, 0x31, 0x2A),
    rule_strong: rgb!(0x4A, 0x44, 0x3A),

    accent: rgb!(0x5F, 0xC0, 0xA6),
    accent_strong: rgb!(0x7A, 0xD3, 0xBA),
    accent_soft: rgb!(0x23, 0x36, 0x30),
    on_accent: rgb!(0x0E, 0x1F, 0x1A),

    success: rgb!(0x6F, 0xBF, 0x8B),
    success_surface: rgb!(0x1E, 0x30, 0x24),
    warning: rgb!(0xE0, 0xB0, 0x5A),
    warning_surface: rgb!(0x33, 0x2A, 0x18),
    danger: rgb!(0xE3, 0x7A, 0x6D),
    danger_surface: rgb!(0x38, 0x21, 0x1E),
    info_surface: rgb!(0x24, 0x27, 0x2A),

    grain_alpha: 20,
    grain_tint: Color32::from_rgba_premultiplied(0xFF, 0xFF, 0xFF, 20),
};

impl Palette {
    /// Pick the palette for an appearance mode.
    pub const fn of(dark: bool) -> Self {
        if dark {
            DARK
        } else {
            LIGHT
        }
    }

    /// Palette matching the current egui visuals.
    pub fn current(ui: &egui::Ui) -> Self {
        Self::of(ui.visuals().dark_mode)
    }

    /// Palette matching an egui context.
    pub fn from_ctx(ctx: &egui::Context) -> Self {
        Self::of(ctx.style().visuals.dark_mode)
    }

    /// A wash behind a card, following the "surface" convention.
    pub fn surface(&self, tone: Tone) -> Color32 {
        match tone {
            Tone::Neutral => self.card,
            Tone::Success => self.success_surface,
            Tone::Warning => self.warning_surface,
            Tone::Danger => self.danger_surface,
            Tone::Info => self.info_surface,
            Tone::Accent => self.accent_soft,
        }
    }

    /// The foreground colour matching a tone.
    pub fn tone_ink(&self, tone: Tone) -> Color32 {
        match tone {
            Tone::Neutral => self.ink,
            Tone::Success => self.success,
            Tone::Warning => self.warning,
            Tone::Danger => self.danger,
            Tone::Info => self.ink_soft,
            Tone::Accent => self.accent,
        }
    }
}

/// Semantic colour roles used by widgets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Accent,
    Success,
    Warning,
    Danger,
    Info,
}

// ---------------------------------------------------------------------------
// Geometry & typography
// ---------------------------------------------------------------------------

/// Width of the navigation rail (icons + labels + padding).
pub const RAIL_WIDTH: f32 = 236.0;
/// Horizontal page padding.
pub const PAGE_PAD: f32 = 22.0;
/// Height of a standard control.
pub const CONTROL_H: f32 = 34.0;

/// Small radius – chips, inputs.
pub const R_SM: u8 = 6;
/// Default radius – buttons, rows.
pub const R_MD: u8 = 9;
/// Large radius – cards.
pub const R_LG: u8 = 13;

/// Corner radius helper.
pub const fn radius(r: u8) -> CornerRadius {
    CornerRadius::same(r)
}

/// Body font size.
pub const FS_BODY: f32 = 13.5;
/// Secondary / hint font size.
pub const FS_SMALL: f32 = 11.5;
/// Card and page titles.
pub const FS_TITLE: f32 = 19.0;
/// Big numbers on stat tiles.
pub const FS_NUMERIC: f32 = 25.0;
/// Monospace log font size.
pub const FS_MONO: f32 = 11.5;

pub fn font(size: f32) -> FontId {
    FontId::proportional(size)
}

pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

/// Page / card title.
pub fn title(text: impl Into<String>) -> RichText {
    RichText::new(text).font(font(FS_TITLE)).strong()
}

/// Section heading inside a card.
pub fn section_title(text: impl Into<String>) -> RichText {
    RichText::new(text).font(font(14.5)).strong()
}

/// Body copy.
pub fn body(text: impl Into<String>) -> RichText {
    RichText::new(text).font(font(FS_BODY))
}

/// Small print.
pub fn small(text: impl Into<String>) -> RichText {
    RichText::new(text).font(font(FS_SMALL))
}

/// Monospace line, used for logs and paths in wells.
pub fn mono_text(text: impl Into<String>) -> RichText {
    RichText::new(text).font(mono(FS_MONO))
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------

/// Font files to look for, in priority order, when scanning a directory.
const FONT_EXTENSIONS: [&str; 3] = ["ttf", "otf", "ttc"];

/// Load the CJK-capable font the whole interface depends on.
///
/// Every label in this app is Chinese, and egui's built-in fonts contain no CJK
/// glyphs at all — without this the entire interface renders as tofu boxes. The
/// previous build carried a font file but never loaded it, and the CI step that
/// produced it copied Microsoft YaHei out of `C:\Windows\Fonts` under a
/// "NotoSansSC" filename, which is both a licensing problem and a lie about the
/// format (`msyh.ttc` is a TrueType *collection*).
///
/// Resolution order:
///
/// 1. A font dropped next to the executable in `fonts/` — lets a distribution
///    ship the OFL-licensed Noto Sans SC without embedding it in the binary.
/// 2. The Windows system CJK fonts, which are present on every modern install
///    and are used in place, never redistributed.
/// 3. Whatever egui ships with, so the app still starts (with missing glyphs)
///    rather than refusing to run.
fn install_fonts(ctx: &egui::Context) {
    // Reading a multi-megabyte font file is not something to repeat on every
    // theme toggle, so this only ever runs once per process.
    static INSTALLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    if INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }

    if let Some((name, index, bytes)) = find_cjk_font() {
        let mut fonts = egui::FontDefinitions::default();

        // `index` selects a face inside a TrueType collection such as msyh.ttc.
        let data = egui::FontData {
            index,
            ..egui::FontData::from_owned(bytes)
        };
        fonts.font_data.insert(name.clone(), std::sync::Arc::new(data));

        // Appended rather than prepended: Latin text keeps egui's own hinted
        // face (which is better at small sizes), and CJK falls through to ours.
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts.families.entry(family).or_default().push(name.clone());
        }

        ctx.set_fonts(fonts);
    }
}

fn find_cjk_font() -> Option<(String, u32, Vec<u8>)> {
    // 1. A font shipped alongside the executable.
    if let Some(found) = find_font_in_dir(&crate::config::base_dir().join("fonts")) {
        return Some(found);
    }

    // 2. System fonts. Index 0 of each collection is a usable CJK face.
    #[cfg(windows)]
    {
        let fonts_dir = std::env::var("SystemRoot")
            .map(|root| std::path::PathBuf::from(root).join("Fonts"))
            .unwrap_or_else(|_| std::path::PathBuf::from("C:\\Windows\\Fonts"));

        for name in [
            "msyh.ttc",   // Microsoft YaHei (Simplified Chinese)
            "msyh.ttf",
            "msyhbd.ttc",
            "Deng.ttf",   // DengXian
            "simhei.ttf", // SimHei
            "simsun.ttc", // SimSun
            "msjh.ttc",   // Microsoft JhengHei (Traditional Chinese)
            "malgun.ttf", // Malgun Gothic (Korean, shares Han glyphs)
        ] {
            let path = fonts_dir.join(name);
            if let Ok(bytes) = std::fs::read(&path) {
                if !bytes.is_empty() {
                    return Some((name.to_string(), 0, bytes));
                }
            }
        }
    }

    None
}

/// First usable font file in a directory, sorted by name for determinism.
fn find_font_in_dir(dir: &std::path::Path) -> Option<(String, u32, Vec<u8>)> {
    let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .map(|ext| {
                    let ext = ext.to_string_lossy().to_ascii_lowercase();
                    FONT_EXTENSIONS.contains(&ext.as_str())
                })
                .unwrap_or(false)
        })
        .collect();

    candidates.sort();

    for path in candidates {
        if let Ok(bytes) = std::fs::read(&path) {
            if !bytes.is_empty() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "bundled-font".to_string());
                return Some((name, 0, bytes));
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Style
// ---------------------------------------------------------------------------

/// Apply the paper style to a context.
pub fn apply(ctx: &egui::Context, dark: bool) {
    let pal = Palette::of(dark);

    install_fonts(ctx);

    let mut style = Style::default();

    // Spacing ------------------------------------------------------------
    style.spacing.item_spacing = Vec2::new(9.0, 7.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(12);
    style.spacing.menu_margin = egui::Margin::same(6);
    style.spacing.indent = 18.0;
    style.spacing.slider_width = 130.0;
    style.spacing.interact_size.y = 24.0;

    // A short animation keeps the UI feeling crisp rather than floaty.
    style.animation_time = 0.11;

    // Slim floating scrollbars.
    style.spacing.scroll.bar_width = 7.0;
    style.spacing.scroll.floating = true;
    style.spacing.scroll.bar_inner_margin = 3.0;
    style.spacing.scroll.bar_outer_margin = 2.0;
    style.spacing.scroll.handle_min_length = 28.0;

    // Typography ---------------------------------------------------------
    style.text_styles = [
        (TextStyle::Heading, font(FS_TITLE)),
        (TextStyle::Body, font(FS_BODY)),
        (TextStyle::Button, font(FS_BODY)),
        (TextStyle::Small, font(FS_SMALL)),
        (TextStyle::Monospace, mono(FS_MONO)),
    ]
    .into();

    // Visuals ------------------------------------------------------------
    let mut v = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };

    v.dark_mode = dark;
    v.override_text_color = None;
    v.panel_fill = pal.paper;
    v.window_fill = pal.card;
    v.window_stroke = hairline(pal.rule);
    v.extreme_bg_color = if dark { pal.sunken } else { pal.card_alt };
    v.faint_bg_color = pal.card_alt;
    v.hyperlink_color = pal.accent;
    v.warn_fg_color = pal.warning;
    v.error_fg_color = pal.danger;
    v.selection.bg_fill = pal.accent.gamma_multiply(0.30);
    v.selection.stroke = hairline(pal.accent);

    // Flat, printed feel: no glossy bevels anywhere.
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = radius(R_SM);
        w.expansion = 0.0;
    }

    v.widgets.noninteractive.bg_fill = pal.card;
    v.widgets.noninteractive.weak_bg_fill = pal.card_alt;
    v.widgets.noninteractive.bg_stroke = hairline(pal.rule);
    v.widgets.noninteractive.fg_stroke = hairline(pal.ink);
    v.widgets.noninteractive.corner_radius = radius(R_MD);

    v.widgets.inactive.bg_fill = pal.card;
    v.widgets.inactive.weak_bg_fill = pal.card_alt;
    v.widgets.inactive.bg_stroke = hairline(pal.rule);
    v.widgets.inactive.fg_stroke = hairline(pal.ink);

    v.widgets.hovered.bg_fill = pal.card_hover;
    v.widgets.hovered.weak_bg_fill = pal.card_hover;
    v.widgets.hovered.bg_stroke = hairline(pal.rule_strong);
    v.widgets.hovered.fg_stroke = hairline(pal.ink);

    v.widgets.active.bg_fill = pal.accent_soft;
    v.widgets.active.weak_bg_fill = pal.accent_soft;
    v.widgets.active.bg_stroke = hairline(pal.accent);
    v.widgets.active.fg_stroke = hairline(pal.ink);

    v.widgets.open.bg_fill = pal.card_alt;
    v.widgets.open.weak_bg_fill = pal.card_alt;
    v.widgets.open.bg_stroke = hairline(pal.rule_strong);
    v.widgets.open.fg_stroke = hairline(pal.ink);

    v.window_corner_radius = radius(R_LG);
    v.menu_corner_radius = radius(R_MD);

    v.window_shadow = egui::epaint::Shadow {
        offset: [0, 6],
        blur: 22,
        spread: 0,
        color: Color32::from_black_alpha(if dark { 140 } else { 48 }),
    };
    v.popup_shadow = egui::epaint::Shadow {
        offset: [0, 4],
        blur: 14,
        spread: 0,
        color: Color32::from_black_alpha(if dark { 130 } else { 40 }),
    };

    style.visuals = v;
    ctx.set_style(style);
}

// ---------------------------------------------------------------------------
// Paper grain
// ---------------------------------------------------------------------------

/// Side length of the (tileable) grain texture, in pixels.
const GRAIN_TEX: usize = 192;
/// Number of lattice cells per texture edge.
const GRAIN_CELLS: usize = 12;

/// Build the tileable paper-grain texture.
///
/// The texture is white with a varying alpha channel, so a single texture can
/// be used for both modes: tint it black to darken light paper, white to lift
/// dark paper. It is uploaded with `wrap_mode = Repeat` so painting it is a
/// single textured quad regardless of window size.
pub fn grain_texture(ctx: &egui::Context) -> egui::TextureHandle {
    let n = GRAIN_TEX;
    let cells = GRAIN_CELLS;

    // Deterministic xorshift so the grain is identical across runs (and
    // therefore across the two modes) without pulling in a rand dependency.
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        ((state >> 40) & 0xFF_FFFF) as f32 / 16_777_216.0
    };

    // Low-frequency lattice -> soft fibre structure.
    let mut lattice = [[0.0f32; GRAIN_CELLS]; GRAIN_CELLS];
    for row in lattice.iter_mut() {
        for value in row.iter_mut() {
            *value = next();
        }
    }

    let smooth = |t: f32| t * t * (3.0 - 2.0 * t);
    let lerp = |a: f32, b: f32, t: f32| a + (b - a) * t;

    let mut rgba = vec![0u8; n * n * 4];
    let scale = cells as f32 / n as f32;

    for y in 0..n {
        for x in 0..n {
            let fx = x as f32 * scale;
            let fy = y as f32 * scale;

            let x0 = fx.floor() as usize % cells;
            let y0 = fy.floor() as usize % cells;
            let x1 = (x0 + 1) % cells;
            let y1 = (y0 + 1) % cells;

            let tx = smooth(fx - fx.floor());
            let ty = smooth(fy - fy.floor());

            let top = lerp(lattice[y0][x0], lattice[y0][x1], tx);
            let bottom = lerp(lattice[y1][x0], lattice[y1][x1], tx);
            let fibre = lerp(top, bottom, ty);

            // High-frequency speckle on top of the fibre.
            let speckle = {
                let mut h = (x as u64)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    ^ (y as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
                h ^= h >> 29;
                h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
                h ^= h >> 32;
                (h & 0xFFFF) as f32 / 65_535.0
            };

            // Bias towards the low end so the grain stays a whisper.
            let value = (fibre * 0.55 + speckle * 0.45).powf(1.9).clamp(0.0, 1.0);

            let idx = (y * n + x) * 4;
            rgba[idx] = 255;
            rgba[idx + 1] = 255;
            rgba[idx + 2] = 255;
            rgba[idx + 3] = (value * 255.0) as u8;
        }
    }

    let image = egui::ColorImage::from_rgba_unmultiplied([n, n], &rgba);
    let options = egui::TextureOptions {
        magnification: egui::TextureFilter::Linear,
        minification: egui::TextureFilter::Linear,
        wrap_mode: egui::TextureWrapMode::Repeat,
        ..Default::default()
    };
    ctx.load_texture("clamav-paper-grain", image, options)
}

/// Paint the paper grain across `rect`.
pub fn paint_grain(
    painter: &egui::Painter,
    rect: egui::Rect,
    texture: &egui::TextureHandle,
    pal: &Palette,
) {
    if !rect.is_positive() {
        return;
    }
    let tile = GRAIN_TEX as f32;
    let uv = egui::Rect::from_min_max(
        egui::pos2(0.0, 0.0),
        egui::pos2(rect.width() / tile, rect.height() / tile),
    );
    painter.image(
        texture.id(),
        rect,
        uv,
        pal.grain_tint.gamma_multiply(pal.grain_alpha as f32 / 255.0),
    );
}

// ---------------------------------------------------------------------------
// Small shared painting helpers
// ---------------------------------------------------------------------------

/// Draw a hairline rule across the current ui, returning its rect.
pub fn rule(ui: &mut egui::Ui) -> egui::Rect {
    let pal = Palette::current(ui);
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 1.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::ZERO, pal.rule);
    rect
}

/// Draw a rule with a short accent-coloured tick at the left, like a printed
/// section marker. Used under page and section headings.
pub fn accent_rule(ui: &mut egui::Ui) {
    let pal = Palette::current(ui);
    let rect = rule(ui);
    let tick = egui::Rect::from_min_size(rect.min, Vec2::new(38.0, 2.0));
    ui.painter()
        .rect_filled(tick, CornerRadius::same(1), pal.accent);
}

/// The single hairline weight used for every rule and outline in the app.
///
/// Centralised so the `f32`/`f64` inference of `Stroke::new` never leaks in as
/// a warning, and so the printed-line weight can be tuned in one place.
pub fn hairline(color: Color32) -> Stroke {
    Stroke::new(1.0_f32, color)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WCAG relative luminance.
    fn luminance(color: Color32) -> f64 {
        fn channel(value: u8) -> f64 {
            let value = value as f64 / 255.0;
            if value <= 0.03928 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        }

        0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
    }

    /// WCAG contrast ratio, always >= 1.
    fn contrast(a: Color32, b: Color32) -> f64 {
        let (x, y) = (luminance(a), luminance(b));
        let (hi, lo) = if x > y { (x, y) } else { (y, x) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// Assert text/background legibility, naming the pair when it regresses.
    fn assert_legible(what: &str, fg: Color32, bg: Color32, minimum: f64) {
        let ratio = contrast(fg, bg);
        assert!(
            ratio >= minimum,
            "{what}: contrast {ratio:.2}:1 is below the required {minimum:.1}:1"
        );
    }

    fn check_palette(name: &str, pal: Palette) {
        // Body copy sits on the page or on a card.
        for (surface, background) in [("paper", pal.paper), ("card", pal.card)] {
            assert_legible(
                &format!("{name}: ink on {surface}"),
                pal.ink,
                background,
                7.0,
            );
            assert_legible(
                &format!("{name}: ink_soft on {surface}"),
                pal.ink_soft,
                background,
                4.5,
            );
            // Hints are set at 11.5px, so they still need to clear 4:1.
            assert_legible(
                &format!("{name}: ink_faint on {surface}"),
                pal.ink_faint,
                background,
                4.0,
            );
        }

        // Accent buttons carry their own foreground and must stay readable.
        assert_legible(&format!("{name}: on_accent"), pal.on_accent, pal.accent, 4.5);
        assert_legible(
            &format!("{name}: danger surface"),
            pal.danger,
            pal.danger_surface,
            4.5,
        );

        // Status text is coloured, and colour alone must not cost legibility.
        for (label, color) in [
            ("danger", pal.danger),
            ("success", pal.success),
            ("warning", pal.warning),
        ] {
            assert_legible(
                &format!("{name}: {label} on paper"),
                color,
                pal.paper,
                4.5,
            );
        }
    }

    #[test]
    fn light_palette_is_legible() {
        check_palette("light", LIGHT);
    }

    #[test]
    fn dark_palette_is_legible() {
        check_palette("dark", DARK);
    }

    #[test]
    fn ink_steps_stay_distinguishable() {
        // The three ink levels must remain a visible hierarchy after any
        // accessibility tweak: body text darkest, hints lightest.
        for (name, pal) in [("light", LIGHT), ("dark", DARK)] {
            let body = contrast(pal.ink, pal.paper);
            let soft = contrast(pal.ink_soft, pal.paper);
            let faint = contrast(pal.ink_faint, pal.paper);

            assert!(
                body > soft && soft > faint,
                "{name}: ink hierarchy broken ({body:.2} / {soft:.2} / {faint:.2})"
            );
            assert!(
                soft - faint >= 0.5,
                "{name}: ink_soft and ink_faint are too close to tell apart \
                 ({soft:.2} vs {faint:.2})"
            );
        }
    }

    #[test]
    fn palette_of_selects_by_mode() {
        assert!(!Palette::of(false).dark);
        assert!(Palette::of(true).dark);
    }
}
