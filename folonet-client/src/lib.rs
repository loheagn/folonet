use tonic::{transport::Channel, Request};

pub mod folonetrpc {
    tonic::include_proto!("folonetrpc");
}

use folonetrpc::{
    server_manager_client::ServerManagerClient, StartServerRequest, StopServerRequest,
};

pub mod config;

async fn get_server_manager_client() -> ServerManagerClient<Channel> {
    // let channel = Channel::from_static("http://[::1]:50051")
    //     .connect()
    //     .await
    //     .unwrap();
    ServerManagerClient::connect("http://[::1]:7788")
        .await
        .unwrap()
}

pub async fn start_server(local_endpoint: String) -> Option<config::ServiceConfig> {
    let mut client = get_server_manager_client().await;
    let server = client
        .start_server(Request::new(StartServerRequest {
            local_endpoint: local_endpoint.clone(),
        }))
        .await
        .unwrap()
        .into_inner();

    if !server.active {
        return None;
    }

    Some(config::ServiceConfig {
        name: server.name.clone(),
        local_endpoint: local_endpoint.clone(),
        servers: vec![server.server_endpoint.clone()],
        is_tcp: true,
    })
}

pub async fn stop_server(local_endpoint: String) {
    let mut client = get_server_manager_client().await;
    let _ = client
        .stop_server(Request::new(StopServerRequest {
            local_endpoint: local_endpoint.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
}

#[cfg(test)]
mod tests {}
