package io.dataease.controller.panel.server;

import cn.hutool.json.JSONUtil;
import com.alibaba.fastjson.JSON;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.dataease.auth.filter.F2CLinkFilter;
import io.dataease.auth.util.JWTUtils;
import io.dataease.commons.constants.SysLogConstants;
import io.dataease.commons.utils.AuthUtils;
import io.dataease.commons.utils.DeLogUtils;
import io.dataease.ext.ExtPanelGroupMapper;
import io.dataease.plugins.common.base.domain.PanelGroupWithBLOBs;
import io.dataease.plugins.common.base.domain.PanelLink;
import io.dataease.controller.panel.api.LinkApi;
import io.dataease.controller.request.chart.ChartExtRequest;
import io.dataease.controller.request.panel.link.*;
import io.dataease.dto.panel.link.GenerateDto;
import io.dataease.dto.panel.link.ValidateDto;
import io.dataease.plugins.common.base.mapper.PanelLinkMappingMapper;
import io.dataease.service.chart.ChartViewService;
import io.dataease.service.panel.PanelLinkService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import org.apache.commons.collections4.CollectionUtils;
import io.dataease.dto.panel.PanelGroupExtDto;
import io.dataease.plugins.common.base.domain.PanelLinkMapping;
import io.dataease.plugins.common.base.domain.PanelLinkMappingExample;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.util.List;
import java.util.Map;

@RestController
@Slf4j
public class LinkServer implements LinkApi {

    @Autowired
    private PanelLinkService panelLinkService;

    @Resource
    private ChartViewService chartViewService;

    @Resource
    private PanelLinkMappingMapper panelLinkMappingMapper;

    @Resource
    private ExtPanelGroupMapper extPanelGroupMapper;

    @Override
    public void replacePwd(@RequestBody PasswordRequest request) {
        panelLinkService.password(request);
    }

    @Override
    public void enablePwd(@RequestBody EnablePwdRequest request) {
        panelLinkService.changeEnablePwd(request);
    }

    @Override
    public void resetOverTime(@RequestBody OverTimeRequest request) {
        panelLinkService.overTime(request);

    }

    @Override
    public void switchLink(@RequestBody LinkRequest request) {
        panelLinkService.changeValid(request);
    }

    @Override
    public GenerateDto currentGenerate(@PathVariable("resourceId") String resourceId) {
        return panelLinkService.currentGenerate(resourceId);
    }

    @Override
    public ValidateDto validate(@RequestBody LinkValidateRequest request) throws Exception {
        log.info("LinkService validate func params:", JSON.toJSONString(request));
        String link = request.getLink();
        link = URLDecoder.decode(link, "UTF-8");
        String json = panelLinkService.decryptParam(link);

        String user = request.getUser();
        user = URLDecoder.decode(user, "UTF-8");
        user = panelLinkService.decryptParam(user);

        ValidateDto dto = new ValidateDto();
        dto.setUserId(user);
        String resourceId = json;
        log.info("访问看板的id: {}", resourceId);
        PanelLink one = panelLinkService.findOne(resourceId, Long.valueOf(user));
        dto.setResourceId(resourceId);
        if (ObjectUtils.isEmpty(one)) {
            dto.setValid(false);
            return dto;
        }
        dto.setValid(one.getValid());
        dto.setEnablePwd(one.getEnablePwd());
        dto.setPassPwd(panelLinkService.validateHeads(one));
        dto.setExpire(panelLinkService.isExpire(one));

        // 不能越权，单点登录前判断看板的用户名是否和单点登录的租户id是否一致
//        PanelLinkMappingExample example = new PanelLinkMappingExample();
//        example.createCriteria().andUuidEqualTo(resourceId);
//        List<PanelLinkMapping> mappings = panelLinkMappingMapper.selectByExample(example);
//        if (CollectionUtils.isNotEmpty(mappings)) {
//            PanelLinkMapping panelLinkMapping = mappings.get(0);
//            List<PanelGroupExtDto> panelList = extPanelGroupMapper.getPanelById(panelLinkMapping.getResourceId());
//            if (CollectionUtils.isNotEmpty(panelList)) {
//                PanelGroupExtDto panelGroupExtDto = panelList.get(0);
//                String username = AuthUtils.getUser().getUsername();
//                log.info("访问看板的用户名称: {}, {}", username, panelGroupExtDto.getTenantId());
//                if (!StringUtils.equals(panelGroupExtDto.getTenantId(), username)) {
//                    log.info("租户:" + username +",越权访问看板，请检查！");
//                    dto.setOwnResource(0);
//                } else {
//                    dto.setOwnResource(1);
//                }
//            }
//        }

        List<PanelGroupExtDto> panelList = extPanelGroupMapper.getPanelById(resourceId);
        log.info("查询到的看板列表: {}", JSONUtil.toJsonStr(panelList));
        if (CollectionUtils.isNotEmpty(panelList)) {
            PanelGroupExtDto panelGroupExtDto = panelList.get(0);
            if(StringUtils.isNotEmpty(request.getToken())) {
                String username = JWTUtils.tokenInfoByToken(request.getToken()).getUsername();
                log.info("jwt存储的用户信息：" + username);
                if (!StringUtils.equals(panelGroupExtDto.getTenantId(), username)) {
                    log.info("租户:" + username +",越权访问看板，请检查！");
                    dto.setOwnResource(0);
                } else {
                    dto.setOwnResource(1);
                }
            }
        }
//        List<PanelGroupExtDto> panelList = extPanelGroupMapper.getPanelById(resourceId);
//        log.info("查询到的看板列表: {}", JSONUtil.toJsonStr(panelList));
//        if (CollectionUtils.isNotEmpty(panelList)) {
//            PanelGroupExtDto panelGroupExtDto = panelList.get(0);
//            log.info("存储的用户信息: {}", JSONUtil.toJsonStr(AuthUtils.getUser()));
//            String username = AuthUtils.getUser().getUsername();
//            log.info("访问看板的用户名称: {}, {}", username, panelGroupExtDto.getTenantId());
//            if (!StringUtils.equals(panelGroupExtDto.getTenantId(), username)) {
//                log.info("租户:" + username +",越权访问看板，请检查！");
//                dto.setOwnResource(0);
//            } else {
//                dto.setOwnResource(1);
//            }
//        }
        return dto;
    }

    @Override
    public boolean validatePwd(@RequestBody PasswordRequest request) throws Exception {
        return panelLinkService.validatePwd(request);
    }

    @Override
    public Object resourceDetail(@PathVariable String resourceId) {
        return panelLinkService.resourceInfo(resourceId);
    }

    @Override
    public Object viewDetail(String viewId, String panelId, ChartExtRequest requestList) throws Exception {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes())
                .getRequest();
        String linkToken = request.getHeader(F2CLinkFilter.LINK_TOKEN_KEY);
        DecodedJWT jwt = JWT.decode(linkToken);
        Long userId = jwt.getClaim("userId").asLong();
        requestList.setUser(userId);
        return chartViewService.getData(viewId, requestList);
    }

    @Override
    public String shortUrl(Map<String, String> param) {
        String resourceId = param.get("resourceId");
        String token = param.get("token");
        return panelLinkService.getShortUrl(resourceId, token);
    }

    @Override
    public void viewLinkLog(LinkViewLogRequest request) {
        String panelId = request.getPanelId();
        Boolean mobile = request.getMobile();
        Long userId = request.getUserId();
        SysLogConstants.OPERATE_TYPE operateType = SysLogConstants.OPERATE_TYPE.PC_VIEW;
        if (ObjectUtils.isNotEmpty(mobile) && mobile) {
            operateType = SysLogConstants.OPERATE_TYPE.MB_VIEW;
        }
        if (ObjectUtils.isEmpty(userId)) return;
        PanelGroupWithBLOBs panelGroupWithBLOBs = panelLinkService.resourceInfo(panelId);
        String pid = panelGroupWithBLOBs.getPid();
        DeLogUtils.save(operateType, SysLogConstants.SOURCE_TYPE.LINK, panelId, pid, userId, SysLogConstants.SOURCE_TYPE.USER);
    }
}
