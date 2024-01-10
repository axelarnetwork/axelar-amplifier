use std::error;

use flow::access_api_client::AccessApiClient;
use flow::*;

pub mod flow {
  tonic::include_proto!("flow.access");
}

pub struct FlowClient<T> {
  pub client: AccessApiClient<T>,
}

impl FlowClient<tonic::transport::Channel> {
    pub async fn new(
      url: &str,
    ) -> Result<FlowClient<tonic::transport::Channel>, Box<dyn error::Error>> {
      let mut client = AccessApiClient::connect(url.to_owned()).await?;
      let request = tonic::Request::new(PingRequest {});
      client.ping(request).await?;
      Ok(FlowClient::<tonic::transport::Channel> { client })
    }

    pub async fn get_transaction_result(
      &mut self,
      id: Vec<u8>,
    ) -> Result<TransactionResultResponse, Box<dyn error::Error>> {
      let request = tonic::Request::new(GetTransactionRequest { id });
      let response = self.client.get_transaction_result(request).await?;
      Ok(response.into_inner())
    }
}