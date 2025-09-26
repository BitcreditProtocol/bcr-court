#[derive(Debug, Clone)]
pub struct BillForList {
    pub id: String,
    pub bill_id: String,
    pub sender_node_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct BillForDetail {
    pub id: String,
    pub bill_id: String,
    pub receiver_node_id: String,
    pub sender_node_id: String,
    pub file_urls: Vec<String>,
    pub hash: String,
    pub signature: String,
    pub created_at: String,
}
