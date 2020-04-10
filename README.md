### 运维管理平台后端

---

* **HostView** 视图，使用channels + paramiko，充当堡垒机的角色

* **SiteView** 视图，记录公司内部所有网站，集中管理

* **ExternalView** 视图，记录公司使用的外部网站

* 使用 **JWK** 认证，将认证信息放到客户端的header中，时长设置为7天
    > 这里因为个人使用，就不保存token到DB中了，相应的在部署时，也就不能启动多进程

---
