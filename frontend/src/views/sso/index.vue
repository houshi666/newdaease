<template>
  <div class="cont">
    <spin v-if="!showError" tip="单点登录认证中..."></spin>
    <div class="error" v-if="showError">
      <span class="error_content">错误内容：{{ message }}</span>
      <div style="margin-top: 30px"><img src="https://gw.alipayobjects.com/zos/rmsportal/RVRUAYdCGeYNBWoKiIwB.svg" alt="">
      </div>
    </div>
  </div>
</template>

<script>

//两个参数，一个是cookie的名子，一个是值
function SetCookie(name,value){
  var Days = 1;//此 cookie 将被保存 1 天
  var exp = new Date();//new Date("December 31, 9998");
  exp.setTime(exp.getTime() + Days*24*60*60*1000);
  document.cookie = name + "="+ escape (value) + ";expires=" + exp.toGMTString();
}

//取cookies函数
function getCookie(name){
  var arr = document.cookie.match(new RegExp("(^| )" + name + "=([^;]*)(;|$)"));
  if (arr != null) return unescape(arr[2]); return null;
}

export default {
  name: 'auth',
  data() {
    return {
      showError: false,
      message: ""
    }
  },
  mounted() {
    let code = this.$route.query.code
    let redirect = this.$route.query.redirect;
    let reqObj = {}
    reqObj.code = code
    // todo 恢复
    if (redirect) {
      reqObj.redirect = redirect
    }

    debugger
    console.log("sso---this.$route.query:", JSON.stringify(this.$route.query))

    if (code) {
      this.$store.dispatch('user/ssoLogin', reqObj).then(res => {
        // // this.$router.push({path: '/'})
        // if (redirect) {
        //   let decodeRedirect = decodeURIComponent(redirect);
        //   console.log("decodeRedirect:", decodeRedirect)
        //   this.$router.push({path: decodeRedirect })
        // } else {
        //   this.$router.push({path: '/'})
        // }
        debugger
        let linkPanelHref = getCookie("linkPanelHref")
        console.log("存储在cookie将要访问的链接为:", linkPanelHref)
        if (linkPanelHref) {
          console.log("单点登录成功，访问看板链接：", linkPanelHref)
          debugger
          window.location.href = linkPanelHref
        } else {
          this.$router.push({path: '/'})
        }

      }).catch(err => {
        this.showError = true
        this.message = err.message
      })
    } else {
      this.showError = true
      this.message = "授权码不存在"
    }
  },
}
</script>

<style scoped lang="less">
.cont {
  text-align: center;
  height: 100%;

  .ant-spin {
    position: relative;
    top: 50%;
    transform: translateY(-50%);
  }

  .error {
    position: relative;
    top: 50%;

    .error_content {
      font-size: 18px;
      font-weight: bold;
    }
  }
}
</style>
