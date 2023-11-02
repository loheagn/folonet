use rust_fsm::*;

state_machine! {
    derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)

    pub TCP(Closed)

    Closed => {
        PassiveOpen => Listen,
        SendSyn => SynSent,
    },

    Listen(ReceiveSyn) => ListenReceiveSyn,
    ListenReceiveSyn(SendSynAck) => SynReceived,

    SynSent => {
        ReceiveSyn => SynSentReceiveSyn,
        ReceiveSynAck => ReceiveSynAckReceiveSynAck,
    },
    SynSentReceiveSyn(SendAckForSyn) => SynReceived,
    ReceiveSynAckReceiveSynAck(SendAckForSyn) => Established,

    SynReceived(RecvAckForSyn) => Established,

    Established => {
        SendFin => FinWait1,
        ReceiveFin => CloseWait,
    },

    CloseWait(SendFin) => LastAck,

    LastAck(RecvAckForFin) => Closed,

    FinWait1 => {
        RecvAckForFin => FinWait2,
        ReceiveFin => FinWait1ReceiveFin,
    },
    FinWait1ReceiveFin(SendAckForFin) => Closing,

    FinWait2(ReceiveFin) =>  FinWait2ReceiveFin,
    FinWait2ReceiveFin(SendAckForFin) => TimeWait,

    Closing(RecvAckForFin) => TimeWait,

    TimeWait(TimeExpired) => Closed,
}
