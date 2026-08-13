use std::sync::Arc;

use super::StartupContext;
use crate::config::EngineConfig;

pub(crate) async fn with_database(
    mut ctx: StartupContext,
    config: &EngineConfig,
) -> crate::Result<StartupContext> {
    let mut db_config = config.database.clone();
    if db_config.node_id.is_none() {
        db_config.node_id = Some(ctx.node_identity.node_id.clone());
    }

    match crate::database::init_database(&db_config, &ctx.run_id).await {
        Ok(Some(db)) => {
            ctx.database_node_id = db_config.node_id.clone();
            let db = Arc::new(db);
            ctx.nbi_collector.attach_database(Arc::clone(&db));
            ctx.database = Some(db);
        }
        Ok(None) => {}
        Err(err) => {
            return Err(crate::Error::Config(format!(
                "database initialization failed: {}",
                err
            )));
        }
    }

    Ok(ctx)
}
