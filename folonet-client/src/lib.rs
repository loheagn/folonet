use tonic::{transport::Channel, Request};

pub mod folonetrpc {
    tonic::include_proto!("folonetrpc");
}

use folonetrpc::{server_manager_client::ServerManagerClient, StartServerRequest};

pub mod config;

async fn get_server_manager_client() -> ServerManagerClient<Channel> {
    // let channel = Channel::from_static("http://[::1]:50051")
    //     .connect()
    //     .await
    //     .unwrap();
    ServerManagerClient::connect("http://[::1]:50051")
        .await
        .unwrap()
}

pub async fn start_server(local_endpoint: String) -> Option<config::ServiceConfig> {
    let mut client = get_server_manager_client().await;
    let server_endpoint = client
        .start_server(Request::new(StartServerRequest {
            local_endpoint: local_endpoint.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .server_endpoint;

    if server_endpoint == local_endpoint {
        return None;
    }

    Some(config::ServiceConfig {
        name: "nginx".to_string(),
        local_endpoint: local_endpoint.clone(),
        servers: vec![server_endpoint],
        is_tcp: true,
    })
}

#[cfg(test)]
mod tests {}
