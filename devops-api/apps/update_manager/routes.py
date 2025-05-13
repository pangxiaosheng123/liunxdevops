"""
更新管理路由

注册更新管理模块的蓝图路由
"""
from flask import Blueprint
from . import update_manager

update_routes = Blueprint('update_routes', __name__)
update_routes.register_blueprint(update_manager, url_prefix='/api/update')