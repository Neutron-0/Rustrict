use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

/// Represents an asset, privilege boundary, or high-value target in the attack graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackNode {
    Host(Ipv4Addr),
    Service(Ipv4Addr, u16),
    Identity(String),
    CrownJewel(Ipv4Addr),
}

/// Represents an exploitable transition or relationship between two attack nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackEdge {
    LateralMovement(String),
    PrivilegeEscalation(String),
    WeakCredential(String),
    UnencryptedService(String),
}

/// Directed graph modeling privilege escalation pathways and lateral movement across assets.
pub struct AttackGraph {
    nodes: HashSet<AttackNode>,
    adj: HashMap<AttackNode, Vec<(AttackNode, AttackEdge)>>,
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            adj: HashMap::new(),
        }
    }

    /// Registers a node in the attack graph.
    pub fn add_node(&mut self, node: AttackNode) {
        self.nodes.insert(node.clone());
        self.adj.entry(node).or_default();
    }

    /// Connects two nodes with an exploitable vector / relationship.
    pub fn add_edge(&mut self, from: AttackNode, to: AttackNode, edge: AttackEdge) {
        self.add_node(from.clone());
        self.add_node(to.clone());
        self.adj.entry(from).or_default().push((to, edge));
    }

    /// Finds all non-cyclic paths from the starting node to any Crown Jewel.
    pub fn find_paths_to_crown_jewel(&self, start: &AttackNode) -> Vec<Vec<AttackNode>> {
        let mut results = Vec::new();
        let mut queue: VecDeque<Vec<AttackNode>> = VecDeque::new();
        queue.push_back(vec![start.clone()]);

        while let Some(current_path) = queue.pop_front() {
            let last_node = current_path.last().unwrap();
            if let AttackNode::CrownJewel(_) = last_node {
                results.push(current_path);
                continue;
            }

            if let Some(neighbors) = self.adj.get(last_node) {
                for (next_node, _) in neighbors {
                    if !current_path.contains(next_node) {
                        let mut next_path = current_path.clone();
                        next_path.push(next_node.clone());
                        queue.push_back(next_path);
                    }
                }
            }
        }

        results
    }
}
