"""
TestAI Agent - Dependency Graph Builder

Creates visual representations of test dependencies
for analysis and optimization.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict
import math


class NodeType(Enum):
    """Types of nodes in the dependency graph."""
    TEST = "test"
    FEATURE = "feature"
    MODULE = "module"
    FIXTURE = "fixture"
    DATA = "data"


class EdgeType(Enum):
    """Types of edges in the dependency graph."""
    DEPENDS_ON = "depends_on"  # Test depends on another test
    USES = "uses"  # Test uses a fixture/data
    TESTS = "tests"  # Test verifies a feature
    BELONGS_TO = "belongs_to"  # Test belongs to a module


class GraphLayout(Enum):
    """Layout algorithms for the graph."""
    HIERARCHICAL = "hierarchical"
    FORCE_DIRECTED = "force_directed"
    CIRCULAR = "circular"
    GRID = "grid"


@dataclass
class GraphNode:
    """A node in the dependency graph."""
    node_id: str
    label: str
    node_type: NodeType
    metadata: Dict[str, Any] = field(default_factory=dict)
    x: float = 0.0
    y: float = 0.0
    size: float = 1.0
    color: str = "#6366f1"  # Default indigo
    cluster: Optional[str] = None


@dataclass
class GraphEdge:
    """An edge in the dependency graph."""
    source: str
    target: str
    edge_type: EdgeType
    weight: float = 1.0
    label: Optional[str] = None
    color: str = "#94a3b8"  # Default slate


@dataclass
class DependencyGraph:
    """A complete dependency graph."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    clusters: Dict[str, List[str]]
    layout: GraphLayout
    metadata: Dict[str, Any] = field(default_factory=dict)


class DependencyGraphBuilder:
    """
    Builds dependency graphs from test suites.

    Creates visual representations showing:
    - Test-to-test dependencies
    - Test-to-fixture relationships
    - Feature coverage mapping
    - Module groupings
    """

    # Colors for different node types
    NODE_COLORS = {
        NodeType.TEST: "#6366f1",      # Indigo
        NodeType.FEATURE: "#10b981",   # Emerald
        NodeType.MODULE: "#f59e0b",    # Amber
        NodeType.FIXTURE: "#8b5cf6",   # Violet
        NodeType.DATA: "#ec4899",      # Pink
    }

    # Colors for different edge types
    EDGE_COLORS = {
        EdgeType.DEPENDS_ON: "#ef4444",  # Red
        EdgeType.USES: "#3b82f6",        # Blue
        EdgeType.TESTS: "#10b981",       # Emerald
        EdgeType.BELONGS_TO: "#94a3b8",  # Slate
    }

    def __init__(self):
        """Initialize the graph builder."""
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._clusters: Dict[str, List[str]] = defaultdict(list)

    def add_test(
        self,
        test_id: str,
        title: str,
        category: Optional[str] = None,
        priority: Optional[str] = None,
        dependencies: Optional[List[str]] = None,
        fixtures: Optional[List[str]] = None,
        features: Optional[List[str]] = None,
    ) -> "DependencyGraphBuilder":
        """Add a test node to the graph."""
        # Create test node
        size = self._priority_to_size(priority)

        self._nodes[test_id] = GraphNode(
            node_id=test_id,
            label=title,
            node_type=NodeType.TEST,
            metadata={
                "category": category,
                "priority": priority,
            },
            size=size,
            color=self.NODE_COLORS[NodeType.TEST],
            cluster=category,
        )

        # Add to cluster
        if category:
            self._clusters[category].append(test_id)

        # Add dependency edges
        if dependencies:
            for dep in dependencies:
                self._edges.append(GraphEdge(
                    source=test_id,
                    target=dep,
                    edge_type=EdgeType.DEPENDS_ON,
                    color=self.EDGE_COLORS[EdgeType.DEPENDS_ON],
                ))

        # Add fixture edges
        if fixtures:
            for fixture in fixtures:
                # Create fixture node if not exists
                fixture_id = f"fixture:{fixture}"
                if fixture_id not in self._nodes:
                    self._nodes[fixture_id] = GraphNode(
                        node_id=fixture_id,
                        label=fixture,
                        node_type=NodeType.FIXTURE,
                        color=self.NODE_COLORS[NodeType.FIXTURE],
                    )

                self._edges.append(GraphEdge(
                    source=test_id,
                    target=fixture_id,
                    edge_type=EdgeType.USES,
                    color=self.EDGE_COLORS[EdgeType.USES],
                ))

        # Add feature edges
        if features:
            for feature in features:
                feature_id = f"feature:{feature}"
                if feature_id not in self._nodes:
                    self._nodes[feature_id] = GraphNode(
                        node_id=feature_id,
                        label=feature,
                        node_type=NodeType.FEATURE,
                        color=self.NODE_COLORS[NodeType.FEATURE],
                    )

                self._edges.append(GraphEdge(
                    source=test_id,
                    target=feature_id,
                    edge_type=EdgeType.TESTS,
                    color=self.EDGE_COLORS[EdgeType.TESTS],
                ))

        return self

    def add_tests_from_suite(
        self,
        tests: List[Dict[str, Any]],
    ) -> "DependencyGraphBuilder":
        """Add multiple tests from a test suite."""
        for test in tests:
            self.add_test(
                test_id=test.get("id", f"test-{len(self._nodes)}"),
                title=test.get("title", "Untitled"),
                category=test.get("category"),
                priority=test.get("priority"),
                dependencies=test.get("dependencies"),
                fixtures=test.get("fixtures"),
                features=test.get("features"),
            )
        return self

    def build(
        self,
        layout: GraphLayout = GraphLayout.FORCE_DIRECTED,
    ) -> DependencyGraph:
        """Build the final graph with layout."""
        nodes = list(self._nodes.values())

        # Apply layout algorithm
        if layout == GraphLayout.HIERARCHICAL:
            self._apply_hierarchical_layout(nodes)
        elif layout == GraphLayout.FORCE_DIRECTED:
            self._apply_force_directed_layout(nodes)
        elif layout == GraphLayout.CIRCULAR:
            self._apply_circular_layout(nodes)
        elif layout == GraphLayout.GRID:
            self._apply_grid_layout(nodes)

        return DependencyGraph(
            nodes=nodes,
            edges=self._edges.copy(),
            clusters=dict(self._clusters),
            layout=layout,
            metadata={
                "total_nodes": len(nodes),
                "total_edges": len(self._edges),
                "clusters": len(self._clusters),
            },
        )

    def find_cycles(self) -> List[List[str]]:
        """Find circular dependencies in the graph."""
        cycles = []
        visited = set()
        rec_stack = set()
        path = []

        def dfs(node_id: str):
            visited.add(node_id)
            rec_stack.add(node_id)
            path.append(node_id)

            # Get neighbors (targets of DEPENDS_ON edges)
            neighbors = [
                e.target for e in self._edges
                if e.source == node_id and e.edge_type == EdgeType.DEPENDS_ON
            ]

            for neighbor in neighbors:
                if neighbor not in visited:
                    cycle = dfs(neighbor)
                    if cycle:
                        return cycle
                elif neighbor in rec_stack:
                    # Found cycle
                    cycle_start = path.index(neighbor)
                    return path[cycle_start:] + [neighbor]

            path.pop()
            rec_stack.remove(node_id)
            return None

        for node_id in self._nodes:
            if node_id not in visited:
                cycle = dfs(node_id)
                if cycle:
                    cycles.append(cycle)

        return cycles

    def find_critical_path(self) -> List[str]:
        """Find the longest dependency chain."""
        # Build adjacency list for depends_on edges
        graph = defaultdict(list)
        for edge in self._edges:
            if edge.edge_type == EdgeType.DEPENDS_ON:
                graph[edge.source].append(edge.target)

        # Find longest path using DFS with memoization
        memo = {}

        def longest_path(node_id: str) -> List[str]:
            if node_id in memo:
                return memo[node_id]

            if not graph[node_id]:
                return [node_id]

            best_path = [node_id]
            for neighbor in graph[node_id]:
                path = longest_path(neighbor)
                if len(path) + 1 > len(best_path):
                    best_path = [node_id] + path

            memo[node_id] = best_path
            return best_path

        # Find longest path from any node
        overall_longest = []
        for node_id in self._nodes:
            path = longest_path(node_id)
            if len(path) > len(overall_longest):
                overall_longest = path

        return overall_longest

    def get_node_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for each node."""
        stats = {}

        for node_id in self._nodes:
            incoming = sum(
                1 for e in self._edges if e.target == node_id
            )
            outgoing = sum(
                1 for e in self._edges if e.source == node_id
            )

            dependencies = sum(
                1 for e in self._edges
                if e.source == node_id and e.edge_type == EdgeType.DEPENDS_ON
            )
            dependents = sum(
                1 for e in self._edges
                if e.target == node_id and e.edge_type == EdgeType.DEPENDS_ON
            )

            stats[node_id] = {
                "incoming_edges": incoming,
                "outgoing_edges": outgoing,
                "dependencies": dependencies,
                "dependents": dependents,
                "is_root": dependencies == 0,
                "is_leaf": dependents == 0,
            }

        return stats

    def _priority_to_size(self, priority: Optional[str]) -> float:
        """Convert priority to node size."""
        sizes = {
            "critical": 2.0,
            "high": 1.5,
            "medium": 1.0,
            "low": 0.75,
        }
        return sizes.get(priority or "medium", 1.0)

    def _apply_hierarchical_layout(self, nodes: List[GraphNode]):
        """Apply hierarchical layout based on dependencies."""
        # Calculate levels
        levels = {}
        node_ids = {n.node_id for n in nodes}

        # Find roots (no incoming DEPENDS_ON edges)
        roots = set(node_ids)
        for edge in self._edges:
            if edge.edge_type == EdgeType.DEPENDS_ON and edge.target in roots:
                roots.discard(edge.source)

        # BFS to assign levels
        current_level = 0
        current_nodes = list(roots)

        while current_nodes:
            for node_id in current_nodes:
                if node_id not in levels:
                    levels[node_id] = current_level

            next_nodes = []
            for node_id in current_nodes:
                for edge in self._edges:
                    if edge.source == node_id and edge.edge_type == EdgeType.DEPENDS_ON:
                        if edge.target not in levels:
                            next_nodes.append(edge.target)

            current_level += 1
            current_nodes = list(set(next_nodes))

        # Assign positions
        level_counts = defaultdict(int)
        for node in nodes:
            level = levels.get(node.node_id, 0)
            count = level_counts[level]
            node.x = count * 150
            node.y = level * 100
            level_counts[level] += 1

    def _apply_force_directed_layout(self, nodes: List[GraphNode]):
        """Apply force-directed layout simulation."""
        if not nodes:
            return

        # Initialize random positions
        import random
        for i, node in enumerate(nodes):
            node.x = random.uniform(0, 800)
            node.y = random.uniform(0, 600)

        # Simple force simulation
        iterations = 50
        repulsion = 1000
        attraction = 0.01

        for _ in range(iterations):
            # Calculate repulsion forces
            forces = {n.node_id: [0.0, 0.0] for n in nodes}

            for i, n1 in enumerate(nodes):
                for j, n2 in enumerate(nodes):
                    if i >= j:
                        continue

                    dx = n2.x - n1.x
                    dy = n2.y - n1.y
                    dist = max(1, math.sqrt(dx * dx + dy * dy))

                    force = repulsion / (dist * dist)
                    fx = force * dx / dist
                    fy = force * dy / dist

                    forces[n1.node_id][0] -= fx
                    forces[n1.node_id][1] -= fy
                    forces[n2.node_id][0] += fx
                    forces[n2.node_id][1] += fy

            # Calculate attraction forces (along edges)
            for edge in self._edges:
                if edge.source not in self._nodes or edge.target not in self._nodes:
                    continue

                n1 = self._nodes[edge.source]
                n2 = self._nodes[edge.target]

                dx = n2.x - n1.x
                dy = n2.y - n1.y
                dist = max(1, math.sqrt(dx * dx + dy * dy))

                force = attraction * dist
                fx = force * dx / dist
                fy = force * dy / dist

                forces[n1.node_id][0] += fx
                forces[n1.node_id][1] += fy
                forces[n2.node_id][0] -= fx
                forces[n2.node_id][1] -= fy

            # Apply forces
            for node in nodes:
                f = forces[node.node_id]
                node.x += max(-50, min(50, f[0]))
                node.y += max(-50, min(50, f[1]))

    def _apply_circular_layout(self, nodes: List[GraphNode]):
        """Apply circular layout."""
        if not nodes:
            return

        n = len(nodes)
        radius = max(100, n * 20)
        center_x, center_y = 400, 300

        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n
            node.x = center_x + radius * math.cos(angle)
            node.y = center_y + radius * math.sin(angle)

    def _apply_grid_layout(self, nodes: List[GraphNode]):
        """Apply grid layout."""
        if not nodes:
            return

        n = len(nodes)
        cols = max(1, int(math.ceil(math.sqrt(n))))
        spacing_x, spacing_y = 150, 100

        for i, node in enumerate(nodes):
            row = i // cols
            col = i % cols
            node.x = col * spacing_x
            node.y = row * spacing_y

    def to_mermaid(self) -> str:
        """Export graph as Mermaid diagram."""
        lines = ["graph TD"]

        # Add nodes with labels
        for node in self._nodes.values():
            shape_start, shape_end = self._get_mermaid_shape(node.node_type)
            safe_label = node.label.replace('"', "'")
            lines.append(f'    {node.node_id}{shape_start}"{safe_label}"{shape_end}')

        # Add edges
        for edge in self._edges:
            arrow = self._get_mermaid_arrow(edge.edge_type)
            if edge.label:
                lines.append(f'    {edge.source} {arrow}|{edge.label}| {edge.target}')
            else:
                lines.append(f'    {edge.source} {arrow} {edge.target}')

        return "\n".join(lines)

    def _get_mermaid_shape(self, node_type: NodeType) -> Tuple[str, str]:
        """Get Mermaid shape for node type."""
        shapes = {
            NodeType.TEST: ("[", "]"),
            NodeType.FEATURE: ("([", "])"),
            NodeType.MODULE: ("[[", "]]"),
            NodeType.FIXTURE: ("{{", "}}"),
            NodeType.DATA: ("[(", ")]"),
        }
        return shapes.get(node_type, ("[", "]"))

    def _get_mermaid_arrow(self, edge_type: EdgeType) -> str:
        """Get Mermaid arrow for edge type."""
        arrows = {
            EdgeType.DEPENDS_ON: "-->",
            EdgeType.USES: "-.->",
            EdgeType.TESTS: "==>",
            EdgeType.BELONGS_TO: "---",
        }
        return arrows.get(edge_type, "-->")

    def to_dot(self) -> str:
        """Export graph as DOT/Graphviz format."""
        lines = [
            "digraph TestDependencies {",
            "    rankdir=TB;",
            "    node [shape=box];",
        ]

        # Group by cluster
        for cluster_name, node_ids in self._clusters.items():
            safe_name = cluster_name.replace(" ", "_")
            lines.append(f'    subgraph cluster_{safe_name} {{')
            lines.append(f'        label="{cluster_name}";')
            for node_id in node_ids:
                if node_id in self._nodes:
                    node = self._nodes[node_id]
                    safe_label = node.label.replace('"', '\\"')
                    lines.append(f'        "{node_id}" [label="{safe_label}"];')
            lines.append("    }")

        # Add unclustered nodes
        for node in self._nodes.values():
            if node.cluster is None:
                safe_label = node.label.replace('"', '\\"')
                lines.append(f'    "{node.node_id}" [label="{safe_label}"];')

        # Add edges
        for edge in self._edges:
            style = ""
            if edge.edge_type == EdgeType.USES:
                style = ' [style=dashed]'
            elif edge.edge_type == EdgeType.TESTS:
                style = ' [style=bold]'
            lines.append(f'    "{edge.source}" -> "{edge.target}"{style};')

        lines.append("}")
        return "\n".join(lines)

    def format_summary(self, graph: DependencyGraph) -> str:
        """Format graph summary as readable text."""
        lines = [
            "=" * 60,
            "  TEST DEPENDENCY GRAPH",
            "=" * 60,
            "",
            f"  Total Nodes: {graph.metadata.get('total_nodes', 0)}",
            f"  Total Edges: {graph.metadata.get('total_edges', 0)}",
            f"  Clusters: {graph.metadata.get('clusters', 0)}",
            f"  Layout: {graph.layout.value}",
            "",
        ]

        # Node breakdown by type
        type_counts = defaultdict(int)
        for node in graph.nodes:
            type_counts[node.node_type.value] += 1

        lines.extend([
            "-" * 60,
            "  NODE BREAKDOWN",
            "-" * 60,
        ])
        for node_type, count in sorted(type_counts.items()):
            lines.append(f"  {node_type}: {count}")

        # Edge breakdown by type
        edge_type_counts = defaultdict(int)
        for edge in graph.edges:
            edge_type_counts[edge.edge_type.value] += 1

        lines.extend([
            "",
            "-" * 60,
            "  EDGE BREAKDOWN",
            "-" * 60,
        ])
        for edge_type, count in sorted(edge_type_counts.items()):
            lines.append(f"  {edge_type}: {count}")

        # Find issues
        cycles = self.find_cycles()
        if cycles:
            lines.extend([
                "",
                "-" * 60,
                "  CIRCULAR DEPENDENCIES (Issues)",
                "-" * 60,
            ])
            for i, cycle in enumerate(cycles[:5]):
                lines.append(f"  {i + 1}. {' -> '.join(cycle)}")

        # Critical path
        critical_path = self.find_critical_path()
        if len(critical_path) > 1:
            lines.extend([
                "",
                "-" * 60,
                "  CRITICAL PATH (Longest Chain)",
                "-" * 60,
                f"  Length: {len(critical_path)} tests",
                f"  Path: {' -> '.join(critical_path[:10])}",
            ])
            if len(critical_path) > 10:
                lines.append(f"  ... and {len(critical_path) - 10} more")

        lines.extend(["", "=" * 60])
        return "\n".join(lines)


def create_dependency_graph_builder() -> DependencyGraphBuilder:
    """Create a dependency graph builder instance."""
    return DependencyGraphBuilder()
