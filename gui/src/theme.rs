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
const TEXT_SECONDARY_LIGHT: Color32 = Color32::from_rgb(117, 117, 117);
const HOVERED_LIGHT: Color32 = Color32::from_rgb(240, 240, 240);

pub const SIDEBAR_WIDTH: f32 = 200.0;

pub const BG_PANEL: Color32 = BG_PANEL_DARK;
pub const BG_CARD: Color32 = BG_CARD_DARK;
pub const TEXT_PRIMARY: Color32 = TEXT_PRIMARY_DARK;
pub const TEXT_SECONDARY: Color32 = TEXT_SECONDARY_DARK;

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

    // Try to load custom font, fallback to default if not available
    let font_path = std::path::Path::new("fonts/NotoSansSC-Regular.ttf");
    if font_path.exists() {
        if let Ok(font_data) = std::fs::read(font_path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "sys".to_owned(),
                std::sync::Arc::new(egui::FontData::from_owned(font_data)),
            );
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .insert(0, "sys".to_owned());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push("sys".to_owned());
            ctx.set_fonts(fonts);
        }
    }
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
