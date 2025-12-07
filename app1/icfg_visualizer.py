#!/usr/bin/env python3
"""
ICFG Visualizer using Graphviz
可视化CPPICFG的节点和边
"""

from ast import boolop
import os
import graphviz
from typing import Dict, List, Set, Optional
import cxxfilt
import pysvf


class ICFGVisualizer:
    def __init__(self, icfg: pysvf.ICFG):
        self.icfg = icfg
        self.dot = graphviz.Digraph(comment='ICFG Visualization')
        self.node_colors = {}
        self.edge_colors = {}

        # 设置图形属性
        self.setup_graph_attributes()

    def setup_graph_attributes(self):
        """设置图形的基本属性"""
        self.dot.attr(rankdir='TB')  # 从上到下布局
        self.dot.attr('node', shape='box', style='rounded,filled')
        self.dot.attr('edge', fontsize='10')

    def get_node_color(self, node: pysvf.ICFGNode, visited: bool) -> str:
        """根据节点类型返回颜色"""
        if not visited:
            return 'gray'
        if isinstance(node, pysvf.CallICFGNode):
            return 'lightblue'
        elif isinstance(node, pysvf.RetICFGNode):
            return 'lightgreen'
        elif isinstance(node, pysvf.IntraICFGNode):
            return 'lightyellow'
        else:
            return 'lightgray'

    def get_node_label(self, node: pysvf.ICFGNode) -> str:
        return node.toString()


    def get_edge_color(self, edge) -> str:
        """根据边类型返回颜色"""
        if isinstance(edge, pysvf.IntraCFGEdge):
            return 'black'
        elif isinstance(edge, pysvf.CallCFGEdge):
            return 'red'
        elif isinstance(edge, pysvf.RetCFGEdge):
            return 'blue'
        else:
            return 'gray'

    def add_node(self, node: pysvf.ICFGNode, visited: bool):
        """添加节点到图形中"""
        node_id = str(node.getId())
        label = self.get_node_label(node)
        color = self.get_node_color(node, visited)

        self.dot.node(node_id, label, fillcolor=color)

    def add_edge(self, edge, src_id: str, dst_id: str):
        """添加边到图形中"""
        color = self.get_edge_color(edge)

        self.dot.edge(src_id, dst_id, color=color)

    def visualize(self, function_name: str, output_file: str = 'icfg_visualization', visited_set: Set= None):
        """生成可视化图形"""
        print("开始生成ICFG可视化...")

        node_set = set()

        # 添加所有节点
        print("添加节点...")
        for node in self.icfg.getNodes():
            if node.getFun() is None:
                continue
            if node.getFun().getName() == function_name:
                if visited_set is not None and node.getId() in visited_set:
                    visited = True
                else:
                    visited = False
                self.add_node(node, visited)
                node_set.add(node)

        # 添加所有边
        print("添加边...")
        edge_count = 0

        for node in node_set:
            for edge in node.getOutEdges():
                if edge.getDstNode() in node_set:
                    self.add_edge(edge, str(node.getId()), str(edge.getDstNode().getId()))
                    edge_count += 1
                elif isinstance(edge.getSrcNode(), pysvf.CallICFGNode):
                    self.add_edge(edge, str(edge.getSrcNode().getId()), str(edge.getSrcNode().getRetICFGNode().getId()))
                    edge_count += 1


        print(f"总共添加了 {edge_count} 条边")

        # 保存图形 - 同时保存DOT和PNG格式
        try:
            # 保存DOT源代码
            self.dot.save(f"{output_file}.dot")
            print(f"DOT源代码已保存为 {output_file}.dot")

        except Exception as e:
            print(f"保存图形时出错: {e}")
            # 保存DOT源代码作为备用
            self.dot.save(f"{output_file}.dot")
            print(f"DOT源代码已保存为 {output_file}.dot")

    def visualize_scc(self, scc: List[str], icfg_nodes: List[pysvf.ICFGNode], visited_set: Set):
        visited_num = 0
        total_num = len(icfg_nodes)
        for node in icfg_nodes:
            if visited_set is not None and node.getId() in visited_set:
                visited = True
                visited_num += 1
            else:
                visited = False
            self.add_node(node, visited)
        for node in icfg_nodes:
            for edge in node.getOutEdges():
                if edge.getDstNode() in icfg_nodes:
                    self.add_edge(edge, str(node.getId()), str(edge.getDstNode().getId()))
                elif isinstance(edge.getSrcNode(), pysvf.CallICFGNode):
                    self.add_edge(edge, str(edge.getSrcNode().getId()), str(edge.getSrcNode().getRetICFGNode().getId()))
        # scc_name is the name of the scc
        scc_name = "_".join(scc)
        # unvisited folder
        unvisited_folder = "unvisited"
        if not os.path.exists(unvisited_folder):
            os.makedirs(unvisited_folder)
        self.dot.save(os.path.join(unvisited_folder, f"{scc_name}.dot"))
        print(f"DOT源代码已保存为 {scc_name}.dot")

        # run command dot -Tsvg ${DOT_FILE} -o ${SVG_FILE}
        dot_file = os.path.join(unvisited_folder, f"{scc_name}.dot")
        svg_file = os.path.join(unvisited_folder, f"{scc_name}.svg")
        os.system(f"dot -Tsvg {dot_file} -o {svg_file}")
        # scc name + coverage
        print(f"{scc_name}: visited {visited_num} / {total_num} nodes")
        # return visited_num, total_num, ratio
        return visited_num, total_num


def create_scc_icfg_visualization(icfg: pysvf.ICFG, scc: List[str], icfg_nodes: List[pysvf.ICFGNode], visited_set: Set):
    visualizer = ICFGVisualizer(icfg)
    return visualizer.visualize_scc(scc, icfg_nodes, visited_set)

def create_icfg_visualization(icfg: pysvf.ICFG, function_name: str, output_file: str = 'icfg_visualization'):
    """便捷函数：创建ICFG可视化"""
    visualizer = ICFGVisualizer(icfg)
    visualizer.visualize(function_name, output_file, None)
    return visualizer

def create_unvisited_icfg_visualization(icfg: pysvf.ICFG, function_name: str, visited: Set, all_nodes: List[pysvf.ICFGNode], output_file: str = 'unvisited_icfg_visualization'):
    visualizer = ICFGVisualizer(icfg)
    visualizer.visualize(function_name, output_file, visited)
    return visualizer


# 示例使用
if __name__ == "__main__":
    # 假设你已经有了ICFG对象
    # icfg = CPPICFG(your_icfg_object)
    # icfg.slice()

    # 创建可视化
    # visualizer = create_icfg_visualization(icfg)

    print("ICFG可视化框架已准备就绪！")
    print("请在你的代码中调用 create_icfg_visualization(icfg) 来生成可视化。")
