<template>
  <div style="height: 100%;">
    <link-error
      v-if="showIndex===0"
      :resource-id="resourceId"
    />
    <link-pwd
      v-if="showIndex===1"
      :resource-id="resourceId"
      :user="userId"
      @fresh-token="refreshToken"
    />
    <link-view
      v-if="showIndex===2"
      :resource-id="resourceId"
      :user="userId"
    />
    <link-expire
      v-if="showIndex===3"
      :resource-id="resourceId"
      :user="userId"
    />
    <own-resource
      v-if="showIndex===4"
      />
  </div>
</template>
<script>
import { getQueryVariable } from '@/utils/index'
import { validate } from '@/api/link'
import LinkView from './view'
import LinkError from './error'
import LinkPwd from './pwd'
import LinkExpire from './overtime'
import OwnResource from './ownresource'
import {getToken, setToken} from "@/utils/auth";
import {findOneWithParent, getVisitToken} from "@/api/panel/panel"

export default {
  components: {
    LinkError, LinkPwd, LinkView, LinkExpire, OwnResource
  },

  data() {
    return {
      resourceId: null,
      userId: null,
      PARAMKEY: 'link',
      link: null,
      user: null,
      visitToken: undefined,
      visitCode: undefined,
      showIndex: -1
    }
  },
  created() {
    this.loadInit()
  },
  methods: {
    async loadInit() {
      console.log("公共分享打开页面中11111--------->")
      this.$store.commit('setPublicLinkStatus', true)
      this.link = this.$route.query.link
      this.user = this.$route.query.user
      this.token = this.$route.query.token
      this.visitToken =  this.$route.query.visitToken
      this.visitCode =  this.$route.query.visitCode

      console.log("delink页面传递的query参数: ", JSON.stringify(this.$route.query))
      let decodeLink = decodeURIComponent(this.link)
      let decodeUser = decodeURIComponent(this.user)

      console.log("link index的link解码---->", decodeLink)
      console.log("link index的user解码---->", decodeUser)

      if (this.visitToken != '' && this.visitToken !== undefined) {
        let visitToken =  decodeURIComponent(this.visitToken)
        console.log("link index的visitCode解码---->", visitToken)
        console.log("79行设置的token:", visitToken)
        setToken(visitToken)
      }

      if (this.visitCode != '' && this.visitCode !== undefined) {
        let visitCode =  decodeURIComponent(this.visitCode)
        console.log("link index的visitCode解码---->", visitCode)
        console.log("94行设置的visitCode:", visitCode)
        setToken(visitCode)
      }


      // todo 恢复
      const hasToken = getToken()
      console.log("hasToken=--------->", hasToken)
      if (!hasToken) {
        let currentUrl = window.location.href
        console.log("当前页面链接--------->", currentUrl)
        // let encodeCurrentUrl = encodeURIComponent(window.location.href)
        let encodeCurrentUrl = window.location.href
        console.log("当前页面链接转码后--------->", encodeCurrentUrl)
        // todo 可能保留
        // window.location.href = `http://10.103.100.84:8001/de-api/api/auth/sso/authorize?redirect=${encodeCurrentUrl}`;
        // window.location.href = `http://10.103.100.84:8001/de-api/api/auth/sso/authorize?redirect=${encodeFakeRedirectUri}`;
        window.location.href = `http://10.103.100.84:8001/de-api/api/auth/sso/authorize`;
      }


      if (!this.link) {
        this.link = getQueryVariable(this.PARAMKEY)
      }
      if (!this.user) {
        this.user = getQueryVariable('user')
      }
      if (!this.link) {
        this.showError()
        return
      }
      if (this.token) {
        console.log("接收到传递来的token:", decodeURIComponent(this.token))
        setToken(decodeURIComponent(this.token))
      }
      const params = this.user ? { link: encodeURIComponent(this.link), user: encodeURIComponent(this.user), token: hasToken } : { link: encodeURIComponent(this.link) }
      console.log("params4delink:", JSON.stringify(params))
      validate(params).then(res => {
        const { resourceId, valid, enablePwd, passPwd, expire, userId, ownResource } = res.data
        this.resourceId = resourceId
        this.userId = userId
        // 如果链接无效 直接显示无效页面
        if (!valid || !resourceId) {
          this.showError()
          return
        }

        if (expire) {
          this.showExpire()
          return
        }

        if (enablePwd && !passPwd) {
          this.showPwd()
          return
        }
        // 0:不是自己的资源， 1：是自己可访问的资源
        if (ownResource !== 1) {
          this.showOwnResource()
          return
        }

        this.showView()
      }).catch(() => {
        this.showError()
      })
    },
    refreshToken() {
      this.loadInit()
    },

    // 显示无效链接
    showError() {
      this.showIndex = 0
    },
    // 显示密码框
    showPwd() {
      this.showIndex = 1
    },
    // 显示仪表板
    showView() {
      this.showIndex = 2
    },
    showExpire() {
      this.showIndex = 3
    },
    showOwnResource() {
      this.showIndex = 4
    }
  }
}
</script>
