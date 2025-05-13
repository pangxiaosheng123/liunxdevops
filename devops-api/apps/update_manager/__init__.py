"""
更新管理模块

提供更新状态查看、版本管理和更新下发功能的API接口
"""
from flask import Blueprint, request, jsonify
from ..update_config import UpdateConfig

update_manager = Blueprint('update_manager', __name__)

# 初始化更新配置
update_config = UpdateConfig(
    check_update_url="http://example.com/api/check_update",
    current_version="1.0.0"
)

@update_manager.route('/check_update', methods=['GET'])
def check_update():
    """检查更新"""
    update_info = update_config.check_for_update()
    return jsonify(update_info)

@update_manager.route('/download_update', methods=['POST'])
def download_update():
    """下载更新"""
    data = request.get_json()
    download_url = data.get('download_url')
    if not download_url:
        return jsonify({"error": "Missing download_url"}), 400
    
    success = update_config.download_update(download_url)
    return jsonify({"success": success})

@update_manager.route('/install_update', methods=['POST'])
def install_update():
    """安装更新"""
    success = update_config.install_update()
    return jsonify({"success": success})

@update_manager.route('/rollback_update', methods=['POST'])
def rollback_update():
    """回滚更新"""
    success = update_config.rollback_update()
    return jsonify({"success": success})