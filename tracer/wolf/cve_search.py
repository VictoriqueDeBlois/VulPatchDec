import os
from datetime import datetime

from vulnerability_analysis.patch_localization.tool import cls_cve_localized_patch, cls_node
from vulnerability_analysis.patch_localization.tool.cls_cve_localized_patch import CVELocalizedPatch
from vulnerability_analysis.patch_localization.tool.tool_main import read_NRD_reports_ref, extract_urls_in_node_website, \
    filter_identified_nodes, extract_and_filter_issueKey_gitrepo_info_in_nodes, search_github_for_cve_fix, \
    confirm_patch, extend_github_commit_node, write_cve_patch_result


def init_and_read_NRD(cve_id):
    cve_patches_obj = cls_cve_localized_patch.CVELocalizedPatch(CVEID=cve_id, sourses=['N', 'R', 'D', 'G'])
    src_refs = read_NRD_reports_ref(cve_id, cve_patches_obj)
    cve_patches_obj.src_refs = src_refs
    return cve_patches_obj


def deep_search_url(cve_patches_obj):
    src_refs = cve_patches_obj.src_refs
    for src in src_refs:  # 该两行代码单独提出来，便于布局好看， RDG，在同一水平
        # 建src Node
        src_node_obj = cls_node.Node(node_content_type='source', node_content=src)
        cve_patches_obj.url_graph.add_edge(parent_node=cve_patches_obj.url_graph.root_node, child_node=src_node_obj)
        # step3: 识别 target_types_of_nodes， 放入graph中
        identified_nodes = cls_node.Node.identify_target_types_of_nodes(url_list=src_refs[src], target_types='all')
        for identified_node in identified_nodes:
            cve_patches_obj.url_graph.add_edge(parent_node=src_node_obj, child_node=identified_node, weight=1)
        # step4: 识别出 nodes to extend, 如：issue node
        nodes_to_extend = [node_ele for node_ele in identified_nodes if
                           node_ele.type not in ['patch_url', 'github_repo_url']]
        count_depth = 2
        while len(nodes_to_extend) and count_depth < 4:
            count_depth += 1
            next_level_nodes_to_extend = []  # 下一层
            for node_ele_to_extend in nodes_to_extend:  # 当前层
                # 循环: step2, step3, step4
                # 分析出 node 网页中的ref
                refs = extract_urls_in_node_website(node_ele_to_extend)
                # 识别target_types_of_nodes, 过滤部分node进行剪枝, 放入graph中
                identified_nodes = cls_node.Node.identify_target_types_of_nodes(url_list=refs,
                                                                                target_types=['issue_url', 'patch_url',
                                                                                              'github_repo_url'])
                identified_nodes = filter_identified_nodes(children_nodes_to_filter=identified_nodes,
                                                           parent_node=node_ele_to_extend)
                added_nodes = []
                for identified_node in identified_nodes:
                    add_result = cve_patches_obj.url_graph.add_edge(parent_node=node_ele_to_extend,
                                                                    child_node=identified_node, weight=1)
                    if add_result:
                        added_nodes.append(identified_node)  # 说明时新增的节点，作为后期 nodes_to_extend的范围
                # 识别出 nodes to extend, 如：issue node
                extend = [node_ele for node_ele in added_nodes if node_ele.type == 'issue_url']
                extend = extend[:5]
                next_level_nodes_to_extend += extend
            nodes_to_extend = next_level_nodes_to_extend
    return cve_patches_obj


def search_commit(cve_patches_obj):
    # step5: 提取graph中 CVEID、Issuekey、github_repo信息
    cve_id = cve_patches_obj.CVEID
    node_list = cve_patches_obj.url_graph.nodes
    issueKey_gitrepo_info = extract_and_filter_issueKey_gitrepo_info_in_nodes(node_list)
    # step6: 于Github中搜索commit,并加入图中
    if 'G' in cve_patches_obj.sources:
        search_github_for_fix_result = search_github_for_cve_fix(CVEID=cve_id,
                                                                 issueKey_gitrepo_info=issueKey_gitrepo_info,
                                                                 CVEID_node=cve_patches_obj.url_graph.root_node)
        for ele in search_github_for_fix_result:
            input_type, input_node, input_content, commits = \
                ele['input_type'], ele['input_node'], ele['input_content'], ele['commits']
            # 建 commit node, 并放入图中
            for commit in commits:
                patch_node_obj = cls_node.Node(node_content_type='url', node_content=commit)
                cve_patches_obj.url_graph.add_edge(parent_node=input_node, child_node=patch_node_obj,
                                                   edge_description='SG')
    return cve_patches_obj


def extend_commit(cve_patches_obj):
    cve_id = cve_patches_obj.CVEID
    # extend
    candidate_patch_nodes = confirm_patch(cve_id, cve_patches_obj)[cve_id]
    extend_github_commit_node(candidate_patch_nodes=candidate_patch_nodes, cve_patches_obj=cve_patches_obj)
    # step7: 保存运行结果
    cve_patches_obj.url_graph.build_graph()  # 存一下图信息
    write_cve_patch_result(cve_patches_obj)
    return cve_patches_obj


def pipeline(func, queue_in, queue_out, path):
    os.makedirs(path, exist_ok=True)
    while True:
        task = queue_in.get()
        if task is None:
            queue_out.put(None)
            break
        last_path, cve_id, consuming_time = task
        begin = datetime.now()
        if os.path.exists(os.path.join(path, f'{cve_id}.pkl')):
            end = datetime.now()
            time = end - begin + consuming_time
            queue_out.put((path, cve_id, time))
            continue
        cve_patches_obj = CVELocalizedPatch.load(last_path, cve_id)
        cve_patches_obj = func(cve_patches_obj)
        cve_patches_obj.save(path)
        end = datetime.now()
        time = end - begin + consuming_time
        queue_out.put((path, cve_id, time))


def cve_search(cve_id):
    cve_patches_obj, src_refs = init_and_read_NRD(cve_id)
    cve_patches_obj = deep_search_url(cve_patches_obj)
    cve_patches_obj = search_commit(cve_patches_obj)
    extend_commit(cve_patches_obj)
