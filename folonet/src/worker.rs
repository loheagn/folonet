use std::fmt::Debug;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;

pub trait MsgHandler: Send + Sync + 'static {
    type MsgType: Send + Sync + 'static + Debug;

    fn handle_message(
        &mut self,
        msg: Self::MsgType,
    ) -> impl std::future::Future<Output = ()> + Send;
}

pub struct MsgWorker<T>
where
    T: MsgHandler,
{
    pub handler: Arc<Mutex<T>>,
    sender: Option<mpsc::Sender<T::MsgType>>,
}

impl<T> MsgWorker<T>
where
    T: MsgHandler,
{
    const CHANNEL_SIZE: usize = 10240;
    pub fn new(msg_handler: T) -> Self {
        let mut worker = MsgWorker {
            handler: Arc::new(Mutex::new(msg_handler)),
            sender: None,
        };
        worker.listen_async();
        worker
    }

    pub fn msg_sender(&self) -> Option<&mpsc::Sender<T::MsgType>> {
        self.sender.as_ref()
    }

    pub fn listen_async(&mut self) {
        let (tx, mut rx) = mpsc::channel::<T::MsgType>(Self::CHANNEL_SIZE);
        let handler = self.handler.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(msg) => {
                                let mut handler = handler.lock().await;
                                handler.handle_message(msg).await;
                            }
                            None => break,
                        }
                    }
                }
                // if let Some(msg) = rx.recv().await {
                //     let mut handler = handler.lock().await;
                //     handler.handle_message(msg).await;
                // }
            }
        });

        self.sender.replace(tx);
    }
}

mod test {

    #[test]
    fn work() {
        use std::{sync::Arc, time::Duration};

        use log::info;
        struct Inner {}
        impl Inner {
            fn echo(&self) {
                info!("inner echo!")
            }
        }
        struct T {
            inner: Arc<Inner>,
        }

        impl T {
            fn listen(&mut self) {
                let inner = self.inner.clone();
                tokio::spawn(async move {
                    loop {
                        inner.echo();
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                });
            }

            fn get_mut_inner(&mut self) -> &mut Arc<Inner> {
                &mut self.inner
            }
        }

        let mut t = T {
            inner: Arc::new(Inner {}),
        };
        t.listen();
        t.get_mut_inner();
    }
}
