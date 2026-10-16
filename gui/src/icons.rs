//! A tiny stroke-based vector icon set.
//!
//! Every glyph is authored in a normalised 24x24 box with a 1.5px-ish weight,
//! so the set scales cleanly from 14px (inline hints) to 40px (page heroes).
//!
//! Using painted vectors instead of emoji has three benefits:
//!
//! * the look is consistent and matches the paper/ink aesthetic,
//! * no multi-megabyte colour-emoji font has to be loaded or rasterised,
//! * behaviour is identical on every platform (no tofu boxes).

use eframe::egui;
use egui::{Color32, CornerRadius, Pos2, Rect, Response, Sense, Shape, Stroke, StrokeKind, Ui, Vec2};

/// The available glyphs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// Empty shield outline.
    Shield,
    /// Shield with a tick – everything is fine.
    ShieldCheck,
    /// Shield with an exclamation mark – attention required.
    ShieldAlert,
    /// 2x2 panel grid – dashboard.
    Layout,
    /// Magnifying glass – scan.
    Magnifier,
    /// Circular arrows – refresh / re-check.
    Refresh,
    /// Arrow into a tray – download / update.
    Download,
    /// Padlock – quarantine.
    Lock,
    /// Sliders – settings.
    Sliders,
    /// Document with ruled lines – logs.
    FileDoc,
    /// Filled triangle – start.
    Play,
    /// Filled square – stop.
    Stop,
    /// Folder.
    Folder,
    /// Bin.
    Trash,
    /// Arrow rising out of a tray – restore.
    Restore,
    /// Tick.
    Check,
    /// Warning triangle.
    Alert,
    /// Circled i.
    Info,
    /// Cross.
    Close,
    /// Stacked discs – signature database.
    Database,
    /// Clock face.
    Clock,
    /// Processor.
    Chip,
    /// Heartbeat trace – realtime activity.
    Pulse,
    /// Right chevron.
    ChevronRight,
}

/// Stroke width for a glyph of the given size.
fn weight(size: f32) -> f32 {
    (size / 13.0).clamp(1.25, 2.1)
}

/// Drawing helper that maps the 24x24 design box onto a real rect.
struct Pen<'a> {
    painter: &'a egui::Painter,
    rect: Rect,
    stroke: Stroke,
    color: Color32,
    scale: f32,
}

impl<'a> Pen<'a> {
    fn new(painter: &'a egui::Painter, rect: Rect, color: Color32, size: f32) -> Self {
        Self {
            painter,
            rect,
            stroke: Stroke::new(weight(size), color),
            color,
            scale: rect.width().min(rect.height()) / 24.0,
        }
    }

    fn at(&self, x: f32, y: f32) -> Pos2 {
        Pos2::new(
            self.rect.min.x + x * self.scale,
            self.rect.min.y + y * self.scale,
        )
    }

    /// Radius in design units -> pixels.
    fn r(&self, r: f32) -> f32 {
        r * self.scale
    }

    fn dot(&self, x: f32, y: f32, r: f32) {
        self.painter
            .circle_filled(self.at(x, y), self.r(r), self.color);
    }

    fn seg(&self, x1: f32, y1: f32, x2: f32, y2: f32) {
        self.painter
            .line_segment([self.at(x1, y1), self.at(x2, y2)], self.stroke);
    }

    fn poly(&self, points: &[(f32, f32)]) {
        let pts: Vec<Pos2> = points.iter().map(|(x, y)| self.at(*x, *y)).collect();
        self.painter.add(Shape::line(pts, self.stroke));
    }

    fn poly_closed(&self, points: &[(f32, f32)]) {
        let pts: Vec<Pos2> = points.iter().map(|(x, y)| self.at(*x, *y)).collect();
        self.painter.add(Shape::closed_line(pts, self.stroke));
    }

    fn tri_filled(&self, points: &[(f32, f32)]) {
        let pts: Vec<Pos2> = points.iter().map(|(x, y)| self.at(*x, *y)).collect();
        self.painter
            .add(Shape::convex_polygon(pts, self.color, Stroke::NONE));
    }

    fn circle(&self, cx: f32, cy: f32, r: f32) {
        self.painter
            .circle_stroke(self.at(cx, cy), self.r(r), self.stroke);
    }

    /// Ellipse sampled from `a0` to `a1` (degrees, 0 = +x, growing clockwise
    /// because screen y points down).
    fn arc(&self, cx: f32, cy: f32, rx: f32, ry: f32, a0: f32, a1: f32) {
        let steps = 20;
        let mut pts = Vec::with_capacity(steps + 1);
        for i in 0..=steps {
            let t = i as f32 / steps as f32;
            let a = (a0 + (a1 - a0) * t).to_radians();
            pts.push(self.at(cx + rx * a.cos(), cy + ry * a.sin()));
        }
        self.painter.add(Shape::line(pts, self.stroke));
    }

    fn ellipse(&self, cx: f32, cy: f32, rx: f32, ry: f32) {
        self.arc(cx, cy, rx, ry, 0.0, 360.0);
    }

    /// Rounded outline rectangle in design units.
    fn rect(&self, x: f32, y: f32, w: f32, h: f32, radius: f32) {
        let r = Rect::from_min_max(self.at(x, y), self.at(x + w, y + h));
        self.painter.rect_stroke(
            r,
            CornerRadius::same((self.r(radius)) as u8),
            self.stroke,
            StrokeKind::Inside,
        );
    }

    fn rect_filled(&self, x: f32, y: f32, w: f32, h: f32, radius: f32) {
        let r = Rect::from_min_max(self.at(x, y), self.at(x + w, y + h));
        self.painter
            .rect_filled(r, CornerRadius::same((self.r(radius)) as u8), self.color);
    }

    /// Arrow head at `(x, y)` pointing towards `angle` (degrees).
    fn head(&self, x: f32, y: f32, angle: f32, len: f32) {
        let tip = self.at(x, y);
        for delta in [150.0_f32, -150.0] {
            let a = (angle + delta).to_radians();
            let p = Pos2::new(
                tip.x + a.cos() * self.r(len),
                tip.y + a.sin() * self.r(len),
            );
            self.painter.line_segment([tip, p], self.stroke);
        }
    }
}

/// Paint an icon inside `rect`.
pub fn draw(painter: &egui::Painter, rect: Rect, icon: Icon, color: Color32, size: f32) {
    // Keep the design box square and centred inside `rect`.
    let side = rect.width().min(rect.height());
    let rect = Rect::from_center_size(rect.center(), Vec2::splat(side));
    let pen = Pen::new(painter, rect, color, size);

    match icon {
        Icon::Shield => {
            pen.poly_closed(&[
                (12.0, 2.6),
                (19.9, 5.8),
                (19.9, 11.4),
                (17.0, 16.3),
                (12.0, 21.4),
                (7.0, 16.3),
                (4.1, 11.4),
                (4.1, 5.8),
            ]);
        }
        Icon::ShieldCheck => {
            pen.poly_closed(&[
                (12.0, 2.6),
                (19.9, 5.8),
                (19.9, 11.4),
                (17.0, 16.3),
                (12.0, 21.4),
                (7.0, 16.3),
                (4.1, 11.4),
                (4.1, 5.8),
            ]);
            pen.poly(&[(8.7, 11.9), (11.2, 14.4), (15.7, 9.2)]);
        }
        Icon::ShieldAlert => {
            pen.poly_closed(&[
                (12.0, 2.6),
                (19.9, 5.8),
                (19.9, 11.4),
                (17.0, 16.3),
                (12.0, 21.4),
                (7.0, 16.3),
                (4.1, 11.4),
                (4.1, 5.8),
            ]);
            pen.seg(12.0, 8.0, 12.0, 13.6);
            pen.dot(12.0, 16.5, 0.95);
        }
        Icon::Layout => {
            pen.rect(3.4, 3.4, 7.6, 7.6, 2.0);
            pen.rect(13.0, 3.4, 7.6, 7.6, 2.0);
            pen.rect(3.4, 13.0, 7.6, 7.6, 2.0);
            pen.rect(13.0, 13.0, 7.6, 7.6, 2.0);
        }
        Icon::Magnifier => {
            pen.circle(10.6, 10.6, 5.7);
            pen.seg(14.8, 14.8, 20.2, 20.2);
        }
        Icon::Refresh => {
            // 280° arc with the gap at the top and an arrow head at the end.
            pen.arc(12.0, 12.0, 6.9, 6.9, -70.0, 210.0);
            pen.head(6.1, 8.6, -30.0, 2.9);
        }
        Icon::Download => {
            pen.seg(12.0, 3.4, 12.0, 15.0);
            pen.head(12.0, 15.0, 90.0, 3.4);
            pen.poly(&[(4.2, 16.2), (4.2, 20.4), (19.8, 20.4), (19.8, 16.2)]);
        }
        Icon::Lock => {
            pen.rect(4.8, 10.4, 14.4, 10.2, 2.4);
            pen.arc(12.0, 10.4, 3.7, 3.7, 180.0, 360.0);
            pen.dot(12.0, 15.5, 1.15);
        }
        Icon::Sliders => {
            pen.seg(3.4, 7.6, 20.6, 7.6);
            pen.circle(9.2, 7.6, 2.4);
            pen.seg(3.4, 16.4, 20.6, 16.4);
            pen.circle(15.0, 16.4, 2.4);
        }
        Icon::FileDoc => {
            pen.rect(4.6, 2.8, 14.8, 18.4, 2.4);
            pen.seg(8.0, 8.2, 16.0, 8.2);
            pen.seg(8.0, 12.0, 16.0, 12.0);
            pen.seg(8.0, 15.8, 13.0, 15.8);
        }
        Icon::Play => {
            pen.tri_filled(&[(7.8, 4.6), (19.6, 12.0), (7.8, 19.4)]);
        }
        Icon::Stop => {
            pen.rect_filled(7.0, 7.0, 10.0, 10.0, 1.8);
        }
        Icon::Folder => {
            pen.poly_closed(&[
                (3.4, 6.4),
                (9.1, 6.4),
                (11.1, 8.9),
                (20.6, 8.9),
                (20.6, 19.0),
                (3.4, 19.0),
            ]);
        }
        Icon::Trash => {
            pen.seg(4.0, 6.6, 20.0, 6.6);
            pen.poly(&[(9.4, 6.6), (9.4, 4.1), (14.6, 4.1), (14.6, 6.6)]);
            pen.poly(&[(6.3, 6.6), (7.4, 20.4), (16.6, 20.4), (17.7, 6.6)]);
            pen.seg(10.5, 10.2, 10.9, 17.2);
            pen.seg(13.5, 10.2, 13.1, 17.2);
        }
        Icon::Restore => {
            pen.poly(&[(3.8, 14.4), (3.8, 20.3), (20.2, 20.3), (20.2, 14.4)]);
            pen.seg(12.0, 17.4, 12.0, 4.2);
            pen.head(12.0, 4.2, -90.0, 3.4);
        }
        Icon::Check => {
            pen.poly(&[(5.4, 12.7), (10.0, 17.2), (18.6, 7.2)]);
        }
        Icon::Alert => {
            pen.poly_closed(&[(12.0, 3.6), (21.4, 19.8), (2.6, 19.8)]);
            pen.seg(12.0, 9.6, 12.0, 14.4);
            pen.dot(12.0, 17.1, 0.95);
        }
        Icon::Info => {
            pen.circle(12.0, 12.0, 8.4);
            pen.dot(12.0, 7.8, 0.95);
            pen.seg(12.0, 11.0, 12.0, 16.6);
        }
        Icon::Close => {
            pen.seg(6.2, 6.2, 17.8, 17.8);
            pen.seg(17.8, 6.2, 6.2, 17.8);
        }
        Icon::Database => {
            pen.ellipse(12.0, 6.6, 6.9, 2.6);
            pen.seg(5.1, 6.6, 5.1, 17.4);
            pen.seg(18.9, 6.6, 18.9, 17.4);
            pen.arc(12.0, 17.4, 6.9, 2.6, 0.0, 180.0);
            pen.arc(12.0, 12.0, 6.9, 2.6, 0.0, 180.0);
        }
        Icon::Clock => {
            pen.circle(12.0, 12.0, 8.4);
            pen.seg(12.0, 6.8, 12.0, 12.3);
            pen.seg(12.0, 12.3, 16.4, 14.7);
        }
        Icon::Chip => {
            pen.rect(6.5, 6.5, 11.0, 11.0, 2.2);
            pen.rect(10.0, 10.0, 4.0, 4.0, 1.0);
            pen.seg(3.4, 9.6, 6.5, 9.6);
            pen.seg(3.4, 14.4, 6.5, 14.4);
            pen.seg(17.5, 9.6, 20.6, 9.6);
            pen.seg(17.5, 14.4, 20.6, 14.4);
            pen.seg(9.6, 3.4, 9.6, 6.5);
            pen.seg(14.4, 3.4, 14.4, 6.5);
            pen.seg(9.6, 17.5, 9.6, 20.6);
            pen.seg(14.4, 17.5, 14.4, 20.6);
        }
        Icon::Pulse => {
            pen.poly(&[
                (2.6, 12.6),
                (7.2, 12.6),
                (9.6, 6.6),
                (13.2, 18.4),
                (15.6, 12.6),
                (21.4, 12.6),
            ]);
        }
        Icon::ChevronRight => {
            pen.poly(&[(9.4, 5.4), (15.9, 12.0), (9.4, 18.6)]);
        }
    }
}

/// Allocate a square of `size` and paint an icon into it.
pub fn paint(ui: &mut Ui, icon: Icon, size: f32, color: Color32) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    if ui.is_rect_visible(rect) {
        draw(ui.painter(), rect, icon, color, size);
    }
    response
}

/// The application mark, rasterised to raw RGBA.
///
/// A jade disc with a white shield, sampled 3×3 per pixel so the disc edge and
/// the shield come out anti-aliased; an aliased circle looks broken at tray
/// sizes. Shared by the taskbar/window icon and the tray icon so there is only
/// one definition of the mark.
pub fn app_icon_rgba(size: u32) -> Vec<u8> {
    const SUBSAMPLES: u32 = 3;
    const JADE: (f32, f32, f32) = (46.0, 139.0, 114.0);

    let size = size.max(8);
    let center = size as f32 / 2.0;
    // Scale the design so the mark keeps its margins at any output size.
    let scale = size as f32 / 32.0;
    let radius = center - 1.5 * scale;
    let samples = (SUBSAMPLES * SUBSAMPLES) as f32;

    let mut rgba = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            let mut disc_hits = 0.0f32;
            let mut shield_hits = 0.0f32;

            for sy in 0..SUBSAMPLES {
                for sx in 0..SUBSAMPLES {
                    let fx = x as f32 + (sx as f32 + 0.5) / SUBSAMPLES as f32;
                    let fy = y as f32 + (sy as f32 + 0.5) / SUBSAMPLES as f32;

                    let dx = fx - center;
                    let dy = fy - center;
                    if (dx * dx + dy * dy).sqrt() <= radius {
                        disc_hits += 1.0;
                        // Convert back into the 32-unit design space.
                        if in_shield(fx / scale, fy / scale, 16.0) {
                            shield_hits += 1.0;
                        }
                    }
                }
            }

            let disc = disc_hits / samples;
            if disc <= 0.0 {
                continue;
            }
            let shield = shield_hits / samples;
            let mix = |base: f32| (base * (1.0 - shield) + 255.0 * shield).round() as u8;

            let index = ((y * size + x) * 4) as usize;
            rgba[index] = mix(JADE.0);
            rgba[index + 1] = mix(JADE.1);
            rgba[index + 2] = mix(JADE.2);
            rgba[index + 3] = (disc * 255.0).round() as u8;
        }
    }

    rgba
}

/// Shield silhouette in a 32-unit design space.
fn in_shield(fx: f32, fy: f32, cx: f32) -> bool {
    let half_width = if (7.5..11.0).contains(&fy) {
        8.5
    } else if (11.0..21.0).contains(&fy) {
        8.5 - (fy - 11.0) * 0.35
    } else if (21.0..26.0).contains(&fy) {
        5.0 - (fy - 21.0)
    } else {
        return false;
    };

    (fx - cx).abs() < half_width
}
