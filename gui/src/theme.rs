use egui::{Color32, CornerRadius, Stroke, Vec2, FontId, FontFamily, Visuals, Style};

pub const ACCENT: Color32 = Color32::from_rgb(0, 150, 136);      // Teal
pub const DANGER: Color32 = Color32::from_rgb(211, 47, 47);
pub const WARNING: Color32 = Color32::from_rgb(255, 160, 0);
pub const SUCCESS: Color32 = Color32::from_rgb(56, 142, 60);

// Dark theme colors
const BG_DARK: Color32 = Color32::from_rgb(18, 18, 18);
const BG_PANEL_DARK: Color32 = Color32::from_rgb(30, 30, 30);
const BG_CARD_DARK: Color32 = Color32::from_rgb(40, 40, 40);
const TEXT_PRIMARY_DARK: Color32 = Color32::from_rgb(240, 240, 240);
const TEXT_SECONDARY_DARK: Color32 = Color32::from_rgb(160, 160, 160);
const HOVERED_DARK: Color32 = Color32::from_rgb(50, 50, 50);

// Light theme colors
const BG_LIGHT: Color32 = Color32::from_rgb(250, 250, 250);
const BG_PANEL_LIGHT: Color32 = Color32::from_rgb(245, 245, 245);
const BG_CARD_LIGHT: Color32 = Color32::from_rgb(255, 255, 255);
const TEXT_PRIMARY_LIGHT: Color32 = Color32::from_rgb(33, 33, 33);
const TEXT_SECONDARY_LIGHT: Color32 = Color32::from_rgb(96, 96, 96);
const HOVERED_LIGHT: Color32 = Color32::from_rgb(240, 240, 240);

pub const SIDEBAR_WIDTH: f32 = 200.0;

pub fn bg_panel(dark_mode: bool) -> Color32 {
    if dark_mode { BG_PANEL_DARK } else { BG_PANEL_LIGHT }
}

pub fn bg_card(dark_mode: bool) -> Color32 {
    if dark_mode { BG_CARD_DARK } else { BG_CARD_LIGHT }
}

pub fn text_primary(dark_mode: bool) -> Color32 {
    if dark_mode { TEXT_PRIMARY_DARK } else { TEXT_PRIMARY_LIGHT }
}

pub fn text_secondary(dark_mode: bool) -> Color32 {
    if dark_mode { TEXT_SECONDARY_DARK } else { TEXT_SECONDARY_LIGHT }
}

pub fn border_color(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(55, 55, 55)
    } else {
        Color32::from_rgb(210, 210, 210)
    }
}

pub fn success_surface(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(30, 60, 50)
    } else {
        Color32::from_rgb(228, 245, 233)
    }
}

pub fn warning_surface(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(50, 35, 20)
    } else {
        Color32::from_rgb(255, 243, 224)
    }
}

pub fn danger_surface(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(60, 30, 30)
    } else {
        Color32::from_rgb(255, 235, 238)
    }
}

pub fn info_surface(dark_mode: bool) -> Color32 {
    if dark_mode {
        Color32::from_rgb(40, 40, 50)
    } else {
        Color32::from_rgb(238, 242, 246)
    }
}

pub fn apply_theme(ctx: &egui::Context, dark_mode: bool) {
    let mut style = Style::default();
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);

    let mut visuals = if dark_mode {
        Visuals::dark()
    } else {
        Visuals::light()
    };

    if dark_mode {
        visuals.panel_fill = BG_DARK;
        visuals.window_fill = BG_PANEL_DARK;
        visuals.extreme_bg_color = BG_CARD_DARK;
        visuals.widgets.noninteractive.bg_fill = BG_CARD_DARK;
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY_DARK);
        visuals.widgets.inactive.bg_fill = BG_CARD_DARK;
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY_DARK);
        visuals.widgets.hovered.bg_fill = HOVERED_DARK;
        visuals.widgets.active.bg_fill = ACCENT;
    } else {
        visuals.panel_fill = BG_LIGHT;
        visuals.window_fill = BG_PANEL_LIGHT;
        visuals.extreme_bg_color = BG_CARD_LIGHT;
        visuals.widgets.noninteractive.bg_fill = BG_CARD_LIGHT;
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY_LIGHT);
        visuals.widgets.inactive.bg_fill = BG_CARD_LIGHT;
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY_LIGHT);
        visuals.widgets.hovered.bg_fill = HOVERED_LIGHT;
        visuals.widgets.active.bg_fill = ACCENT;
    }

    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(6);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
    visuals.widgets.active.corner_radius = CornerRadius::same(6);
    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.4);

    style.visuals = visuals;
    ctx.set_style(style);

    // Load Chinese + Emoji fonts with fallback chain
    let chinese_font = load_chinese_font();
    let emoji_font = load_emoji_font();
    
    if chinese_font.is_some() || emoji_font.is_some() {
        let mut fonts = egui::FontDefinitions::default();
        
        // Load Chinese font
        if let Some(data) = chinese_font {
            fonts.font_data.insert(
                "chinese".to_owned(),
                std::sync::Arc::new(egui::FontData::from_owned(data)),
            );
            
            // Set Chinese font as first priority
            fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "chinese".to_owned());
            fonts.families.entry(FontFamily::Monospace).or_default().push("chinese".to_owned());
        }
        
        // Load Emoji font
        if let Some(data) = emoji_font {
            fonts.font_data.insert(
                "emoji".to_owned(),
                std::sync::Arc::new(egui::FontData::from_owned(data)),
            );
            
            // Add Emoji font as fallback
            fonts.families.entry(FontFamily::Proportional).or_default().push("emoji".to_owned());
            fonts.families.entry(FontFamily::Monospace).or_default().push("emoji".to_owned());
        }
        
        ctx.set_fonts(fonts);
    }
}

/// Load Chinese font with fallback chain:
/// 1. Local fonts/NotoSansSC-Regular.ttf (for packaged builds)
/// 2. System fonts (for development)
fn load_chinese_font() -> Option<Vec<u8>> {
    // Try local font first
    let local_font = std::path::Path::new("fonts/NotoSansSC-Regular.ttf");
    if local_font.exists() {
        if let Ok(data) = std::fs::read(local_font) {
            return Some(data);
        }
    }

    // Fallback to system fonts
    #[cfg(target_os = "windows")]
    {
        let system_fonts = [
            "C:\\Windows\\Fonts\\msyh.ttc",      // Microsoft YaHei
            "C:\\Windows\\Fonts\\simsun.ttc",    // SimSun
            "C:\\Windows\\Fonts\\simhei.ttf",    // SimHei
            "C:\\Windows\\Fonts\\msyhbd.ttc",    // YaHei Bold
            "C:\\Windows\\Fonts\\simkai.ttf",    // KaiTi
        ];

        for font_path in &system_fonts {
            if let Ok(data) = std::fs::read(font_path) {
                return Some(data);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // For non-Windows platforms, try common Chinese font locations
        let system_fonts = [
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/System/Library/Fonts/PingFang.ttc",
        ];

        for font_path in &system_fonts {
            if let Ok(data) = std::fs::read(font_path) {
                return Some(data);
            }
        }
    }

    None
}

/// Load Emoji font for proper emoji display
fn load_emoji_font() -> Option<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        let emoji_fonts = [
            "C:\\Windows\\Fonts\\seguiemj.ttf",  // Segoe UI Emoji
            "C:\\Windows\\Fonts\\seguisym.ttf",  // Segoe UI Symbol
        ];

        for font_path in &emoji_fonts {
            if let Ok(data) = std::fs::read(font_path) {
                return Some(data);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(data) = std::fs::read("/System/Library/Fonts/Apple Color Emoji.ttc") {
            return Some(data);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let emoji_fonts = [
            "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
            "/usr/share/fonts/truetype/ancient-scripts/Symbola.ttf",
        ];

        for font_path in &emoji_fonts {
            if let Ok(data) = std::fs::read(font_path) {
                return Some(data);
            }
        }
    }

    None
}

pub fn heading(text: &str) -> egui::RichText {
    egui::RichText::new(text)
        .font(FontId::proportional(22.0))
}

pub fn subheading(text: &str) -> egui::RichText {
    egui::RichText::new(text)
        .font(FontId::proportional(15.0))
}

pub fn accent_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(Color32::WHITE)
            .font(FontId::proportional(15.0)),
    )
    .fill(ACCENT)
    .corner_radius(CornerRadius::same(8))
    .min_size(Vec2::new(120.0, 36.0))
}

pub fn danger_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(Color32::WHITE)
            .font(FontId::proportional(14.0)),
    )
    .fill(DANGER)
    .corner_radius(CornerRadius::same(8))
    .min_size(Vec2::new(100.0, 32.0))
}
