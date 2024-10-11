package io.dataease.dto.panel;

import io.dataease.plugins.common.base.domain.PanelGroupWithBLOBs;
import io.dataease.plugins.common.model.ITreeBase;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.util.List;

/**
 * Author: youlei
 * Date: 2023-05-18
 * Description:
 */
@Data
public class PanelGroupExtShowDto {
    @ApiModelProperty("id")
    private String id;
    @ApiModelProperty("租户id")
    private String tenantId;
    @ApiModelProperty("缩略图文件路径")
    private String pictureUrl;
    @ApiModelProperty("看板url")
    private String webUrl;
}
