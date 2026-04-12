use crate::prelude::*;

pub struct Report {
    pub title: String,
    pub generated_at: Timestamp,
    pub flows: Vec<FlowSummary>,
    pub events: Vec<EventSummary>,
    pub iocs: Vec<IoCSummary>,
}

#[derive(Debug, Clone)]
pub struct FlowSummary {
    pub flow_id: String,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: i64,
    pub process: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EventSummary {
    pub event_type: String,
    pub timestamp: Timestamp,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct IoCSummary {
    pub ioc_type: String,
    pub value: String,
    pub confidence: f32,
    pub source: String,
}

pub struct ReportBuilder {
    flows: Vec<Flow>,
    events: Vec<nettrap_events::Event>,
    iocs: Vec<nettrap_ioc::IoC>,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            flows: Vec::new(),
            events: Vec::new(),
            iocs: Vec::new(),
        }
    }

    pub fn add_flow(mut self, flow: Flow) -> Self {
        self.flows.push(flow);
        self
    }

    pub fn add_event(mut self, event: nettrap_events::Event) -> Self {
        self.events.push(event);
        self
    }

    pub fn add_ioc(mut self, ioc: nettrap_ioc::IoC) -> Self {
        self.iocs.push(ioc);
        self
    }

    pub fn add_flows(mut self, flows: impl IntoIterator<Item = Flow>) -> Self {
        self.flows.extend(flows);
        self
    }

    pub fn build(self) -> Report {
        let flow_summaries: Vec<FlowSummary> = self
            .flows
            .iter()
            .map(|f| FlowSummary {
                flow_id: f.id.to_string(),
                src: format!("{}:{}", f.five_tuple.src_ip, f.five_tuple.src_port),
                dst: format!("{}:{}", f.five_tuple.dst_ip, f.five_tuple.dst_port),
                protocol: format!("{:?}", f.five_tuple.protocol),
                bytes_sent: f.metadata.bytes_sent,
                bytes_received: f.metadata.bytes_received,
                duration_ms: f.duration_ms(),
                process: f.metadata.process.as_ref().map(|p| p.name.clone()),
            })
            .collect();

        let event_summaries: Vec<EventSummary> = self
            .events
            .iter()
            .map(|e| EventSummary {
                event_type: e.event_type().to_string(),
                timestamp: e.timestamp(),
                summary: format!("{:?}", e),
            })
            .collect();

        let ioc_summaries: Vec<IoCSummary> = self
            .iocs
            .iter()
            .map(|i| IoCSummary {
                ioc_type: format!("{:?}", i.ioc_type),
                value: i.value.clone(),
                confidence: i.confidence,
                source: i.source.clone(),
            })
            .collect();

        Report {
            title: "NetTrap Analysis Report".to_string(),
            generated_at: now(),
            flows: flow_summaries,
            events: event_summaries,
            iocs: ioc_summaries,
        }
    }
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn generate_report(
    flows: &[Flow],
    events: &[nettrap_events::Event],
    iocs: &[nettrap_ioc::IoC],
) -> Report {
    let mut builder = ReportBuilder::new().add_flows(flows.iter().cloned());
    for event in events {
        builder = builder.add_event(event.clone());
    }
    for ioc in iocs {
        builder = builder.add_ioc(ioc.clone());
    }
    builder.build()
}
