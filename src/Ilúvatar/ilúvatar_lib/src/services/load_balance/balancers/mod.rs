pub mod round_robin;
pub mod least_loaded;

#[macro_export]
macro_rules! send_invocation {
  ($func:expr, $json_args:expr, $tid:expr, $worker_fact:expr, $health:expr, $worker:expr) => {
    {
      info!(tid=%$tid, fqdn=%$func.fqdn, wprler=%$worker.name, "invoking function on worker");

      let mut api = $worker_fact.get_worker_api(&$worker, $tid).await?;
      let (result, duration) = api.invoke($func.function_name.clone(), $func.function_version.clone(), $json_args, None, $tid.clone()).timed().await;
      let result = match result {
        Ok(r) => r,
        Err(e) => {
          $health.schedule_health_check($health.clone(), $worker, $tid, Some(Duration::from_secs(1)));
          anyhow::bail!(e)
        },
      };
      debug!(tid=%$tid, json=%result.json_result, "invocation result");
      Ok( (result, duration) )
    }
  };
}

#[macro_export]
macro_rules! prewarm {
  ($func:expr, $tid:expr, $worker_fact:expr, $health:expr, $worker:expr) => {
    {
      info!(tid=%$tid, fqdn=%$func.fqdn, worker=%$worker.name, "prewarming function on worker");
      let mut api = $worker_fact.get_worker_api(&$worker, $tid).await?;
      let (result, duration) = api.prewarm($func.function_name.clone(), $func.function_version.clone(), None, None, None, $tid.clone()).timed().await;
      let result = match result {
        Ok(r) => r,
        Err(e) => {
          $health.schedule_health_check($health.clone(), $worker, $tid, Some(Duration::from_secs(1)));
          anyhow::bail!(e)
        }
      };
      debug!(tid=%$tid, result=?result, "prewarm result");
      Ok(duration)
    }
  }
}

#[macro_export]
macro_rules! send_async_invocation {
  ($func:expr, $json_args:expr, $tid:expr, $worker_fact:expr, $health:expr, $worker:expr) => {
    {
      info!(tid=%$tid, fqdn=%$func.fqdn, worker=%$worker.name, "invoking function async on worker");

      let mut api = $worker_fact.get_worker_api(&$worker, $tid).await?;
      let (result, duration) = api.invoke_async($func.function_name.clone(), $func.function_version.clone(), $json_args, None, $tid.clone()).timed().await;
      let result = match result {
        Ok(r) => r,
        Err(e) => {
          $health.schedule_health_check($health.clone(), $worker, $tid, Some(Duration::from_secs(1)));
          anyhow::bail!(e)
        },
      };
      debug!(tid=%$tid, result=%result, "invocation result");
      Ok( (result, $worker, duration) )
    }
  }
}