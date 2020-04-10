from django.shortcuts import HttpResponse
from django.views import View
from .models import HostInfo, SiteUrl, External
from django.http import JsonResponse
from django.db.utils import IntegrityError
from django.utils.decorators import method_decorator
from django.contrib.auth import authenticate
import python_jwt as jwt
import jwcrypto.jwk as jwk
import datetime
from .utils import TokenOP, Logger
from django.core import serializers
import traceback

# Create your views here.

# 生成一个Json Web Key(JWK) 对象，用于生成Json Web Token(JWT)时的priv_key参数
key = jwk.JWK.generate(kty='RSA', size=2048)
# 定义生成JWT时的签名算法
alg = 'PS256'

logger = Logger()

def auth(func):
    def wrapper(request, *args, **kwargs):
        # if 'HTTP_X_FORWARDED_FOR' in request.META:
        #     ip = request.META['HTTP_X_FORWARDED_FOR']  # 获取代理前客户端的真实IP地址
        # else:
        #     ip = request.META['REMOTE_ADDR']  # 获取客户端IP地址
        token = request.headers.get('token', None)
        if token:
            try:
                header, payload = jwt.verify_jwt(token, key, [alg, ])  # 获取JWT中的信息
                request.user = payload['user']
                if not request.user:
                    result = {'status': 402, 'message': '认证失败'}
                    logger.error('认证失败，未知用户')
                    return JsonResponse(result)
                else:
                    token_black_list = TokenOP(request.user, token)
                    if not token_black_list.is_valid_token():  # 验证token是否在黑名单中
                        result = {'status': 402, 'message': '认证失败'}
                        logger.error('认证失败，token失效')
                        return JsonResponse(result)
            except Exception as e:
                result = {'status': 402, 'message': '无效的token'}
                logger.error('认证失败，无效的token')
                return JsonResponse(result)
        else:
            logger.error('认证失败，无效的token')
            return JsonResponse({'status': 402, 'message': '无效的token'})
        logger.debug('认证通过: {}'.format(request.user))
        return func(request, *args, **kwargs)

    return wrapper


class LogoutView(View):

    def post(self, request):
        try:
            token = request.headers.get('token')
            header, payload = jwt.verify_jwt(token, key, [alg, ])
            token_black_list = TokenOP(payload['user'], token)
            token_black_list.append_to_black_list()
        except Exception as e:
            pass
        finally:
            logger.warning('退出登录: {}'.format(payload['user']))
            return JsonResponse({'status': 200, 'message': '退出登录'})


class MyLoginView(View):

    def post(self, request):
        username = request.POST.get('username', None)
        password = request.POST.get('password', None)
        user = authenticate(request, username=username, password=password)
        if user is not None:
            payload = {'user': username}
            token = jwt.generate_jwt(payload, key, alg, datetime.timedelta(days=7))  # 生成JWT
            logger.info('登陆成功: {}'.format(username))
            return JsonResponse({'status': 200, 'message': '登陆成功', 'token': token, 'user': username})
        else:
            logger.error('登陆失败: {}'.format(username))
            return JsonResponse({'status': 500, 'message': '登陆失败'})


@method_decorator(auth, 'dispatch')
class HostView(View):

    def get(self, request):
        hosts_obj = HostInfo.objects.values(
            'host_name', 'host_addr', 'host_remarks', 'physical_equipment', 'host_spec',
            'host_createTime', 'host_os', 'host_user', 'host_port', 'host_key'
        )
        hosts = list(hosts_obj)
        hosts.sort(key=lambda x: x['host_createTime'], reverse=True)
        logger.debug('获取hosts成功: {}'.format(hosts))
        result = {'status': 200, 'message': hosts}
        return JsonResponse(result, safe=False)

    def post(self, request):
        result = {'status': 200, 'message': ''}
        actions = ['add', 'edit']
        host_dict = {
            'host_name': '', 'host_remarks': '', 'physical_equipment': '', 'host_spec': '', 'host_os': '',
            'host_port': '', 'host_user': '', 'host_key': ''
        }
        addr = request.POST.get('host_addr')
        action = request.POST.get('action')
        if action not in actions:
            result['status'] = 500
            result['message'] = 'Illegal action'
            logger.error('非法操作: {}/{}'.format(addr, action))
            return JsonResponse(result)
        obj = HostInfo.objects.filter(host_addr=addr)
        for key in host_dict:
            if key == 'physical_equipment':
                if request.POST.get(key) == 'true':
                    host_dict[key] = True
                else:
                    host_dict[key] = False
                continue
            host_dict[key] = request.POST.get(key)
        if action == 'add':
            host_dict['host_addr'] = addr
            try:
                HostInfo.objects.create(**host_dict)
            except IntegrityError:
                result['status'] = 500
                result['message'] = '主机地址已存在'
                logger.warning('主机地址已存在: {}'.format(addr))
            except Exception as e:
                result['status'] = 500
                result['message'] = str(e)
                logger.error('添加主机 {} 失败: {}'.format(addr, traceback.format_exc().__str__()))
        else:
            try:
                obj.update(**host_dict)
                new_obj = serializers.serialize("json", HostInfo.objects.filter(host_addr=addr))
                result['host'] = new_obj
                result['message'] = '修改主机 {} 成功'.format(addr)
                logger.info('修改主机 {} 成功'.format(addr))
            except Exception as e:
                result['status'] = 500
                result['message'] = str(e)
                logger.error('修改主机 {} 失败: {}'.format(addr, traceback.format_exc().__str__()))
        return JsonResponse(result, safe=False)


@method_decorator(auth, 'dispatch')
class SiteView(View):

    def get(self, request):
        sites_obj = SiteUrl.objects.values('site_name', 'site_url', 'site_remarks', 'site_tags', 'auth')
        sites = []
        for site in sites_obj:
            if site['auth']:
                site['auth'] = 'auth'
            sites.append(site)
        result = {'status': 200, 'message': sites}
        logger.debug('获取sites成功: {}'.format(str(sites)))
        return JsonResponse(result, safe=False)

    def post(self, request):
        actions = ['add', 'edit', 'del', 'auth']
        site_name = request.POST.get('site_name')
        site_url = request.POST.get('site_url')
        site_remarks = request.POST.get('site_remarks')
        site_tags = request.POST.get('site_tags')
        action = request.POST.get('action')
        if action not in actions:
            logger.error('非法操作: {}/{}'.format(site_url, action))
            return JsonResponse({'status': 500, 'message': '非法操作'})
        site_dict = {'site_name': site_name, 'site_remarks': site_remarks, 'site_tags': site_tags}
        if action == 'add':
            site_auth = request.POST.get('auth')
            site_dict['site_url'] = site_url
            site_dict['auth'] = site_auth
            try:
                SiteUrl.objects.create(**site_dict)
                logger.info('添加site {} 成功'.format(site_url))
                return JsonResponse({'status': 200, 'message': '添加Site {} 成功'.format(site_name), 'site': serializers.serialize("json", SiteUrl.objects.filter(site_url=site_url))})
            except IntegrityError:
                logger.error('添加site {} 失败，URL已存在'.format(site_url))
                return JsonResponse({'status': 500, 'message': 'URL已存在'})
            except Exception as e:
                logger.error('添加site {} 失败: {}'.format(site_url, traceback.format_exc().__str__()))
                return JsonResponse({'status': 500, 'message': str(e)})
        elif action == 'del':
            try:
                SiteUrl.objects.filter(site_url = site_url).delete()
            except Exception as e:
                logger.debug('删除site {} 失败: {}'.format(site_url, traceback.format_exc().__str__()))
            finally:
                logger.info('删除site {} 成功'.format(site_url))
                return JsonResponse({'status': 200, 'message': "删除Site {} 成功".format(site_url)})
        elif action == 'auth':
            phrase = request.POST.get('phrase')
            if phrase != 'bloke':
                logger.error('site口令错误: {}'.format(phrase))
                return JsonResponse({'status': 403, 'message': '口令错误'})
            obj = SiteUrl.objects.filter(site_url = site_url)
            if obj:
                logger.info('获取 {} 登录信息成功'.format(site_url))
                return JsonResponse({'status': 200, 'auth': obj[0].auth})
            else:
                logger.info('未找到 {} 的登录信息'.format(site_url))
                return JsonResponse({'status': 404, 'message': '未找到 {} 的记录'.format(site_url)})
        else:
            try:
                site_obj = SiteUrl.objects.filter(site_url=site_url)
                site_obj.update(**site_dict)
                logger.info('修改site {} 成功: {}'.format(site_url, site_dict.__str__()))
                return JsonResponse({'status': 200, 'message': '修改Site {} 成功'.format(site_name), 'site': serializers.serialize("json", SiteUrl.objects.filter(site_url=site_url))})
            except Exception as e:
                logger.error('修改site {} 失败: {}'.format(site_url, traceback.format_exc().__str__()))
                return JsonResponse({'status': 500, 'message': str(e)})


@method_decorator(auth, 'dispatch')
class ExternalView(View):

    def get(self, request):
        external_obj = External.objects.values('external_name', 'external_url', 'external_remarks')
        external = list(external_obj)
        result = {'status': 200, 'message': external}
        logger.info('获取external成功')
        return JsonResponse(result)

    def post(self, request):
        external_url = request.POST.get('external_url')
        phrase = request.POST.get('phrase')
        if phrase != 'bloke':
            logger.error('external口令错误: {}'.format(phrase))
            return JsonResponse({'status': 403, 'message': '口令错误'})
        obj = External.objects.filter(external_url=external_url)
        if obj:
            logger.info('获取 {} 登录信息成功: {}'.format(external_url, obj[0].external_auth))
            return JsonResponse({'status': 200, 'auth': obj[0].external_auth})
        else:
            logger.error('获取 {} 登录信息失败: {}'.format(external_url, traceback.format_exc().__str__()))
            return JsonResponse({'status': 500, 'message': '未找到 {} 的相关信息'.format(external_url)})

