use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub struct FlowWidget {
    flows: Vec<String>,
}

impl FlowWidget {
    pub fn new(flows: Vec<String>) -> Self {
        Self { flows }
    }

    pub fn render(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let items: Vec<ListItem> = self
            .flows
            .iter()
            .take(area.height as usize)
            .map(|f| ListItem::new(f.clone()))
            .collect();

        let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Flows"));

        frame.render_widget(list, area);
    }
}

pub fn draw_tui(frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ])
        .split(frame.area());

    let title = Paragraph::new("NetTrap - Malware Network Analysis Engine")
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let stats = Paragraph::new("Statistics:\n  Flows: 0\n  Packets: 0\n  Bytes: 0")
        .style(Style::default())
        .block(Block::default().borders(Borders::ALL).title("Stats"));
    frame.render_widget(stats, chunks[1]);

    let events = Paragraph::new("Recent Events:\n  - None")
        .style(Style::default())
        .block(Block::default().borders(Borders::ALL).title("Events"));
    frame.render_widget(events, chunks[2]);
}
