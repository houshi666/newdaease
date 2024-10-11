package io.dataease.dto.panel;

import io.dataease.dto.chart.ChartViewDTO;
import io.dataease.plugins.common.base.domain.PanelGroupWithBLOBs;
import io.dataease.plugins.common.base.domain.PanelWatermark;
import io.dataease.plugins.common.model.ITreeBase;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * Author: youlei
 * Date: 2023-05-18
 * Description:
 */
@Data
public class PanelGroupExtDto extends PanelGroupWithBLOBs implements ITreeBase<PanelGroupExtDto> {
    @ApiModelProperty("租户id")
    private String tenantId;
    @ApiModelProperty("缩略图文件路径")
    private String pictureUrl;
    @ApiModelProperty("子节点")
    private List<PanelGroupExtDto> children;
}
