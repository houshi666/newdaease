package io.dataease.service.panel;

import cn.hutool.core.date.DateTime;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.thread.ThreadUtil;
import cn.hutool.json.JSONUtil;
import io.dataease.ext.ExtPanelGroupMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.openqa.selenium.*;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.io.File;
import java.util.concurrent.*;

/**
 * @author zhangdelei
 * @description
 * @time 2023/3/2
 */
@Slf4j
@Service
public class WebService {

    @Value("${google.chrome.driver.path}")
    private String driverPath;
    @Value("${upload.path}")
    private String uploadPath;
    @Value("${picture.view.path}")
    private String pictureViewPath;

    @Resource
    private ExtPanelGroupMapper extPanelGroupMapper;

//    @Async("threadPoolTaskExecutor")
//    @Transactional(rollbackFor = Exception.class)
//    public void generatorAsync(String path, long loadTime, String resourceId) {
//        log.info(Thread.currentThread().getName() + "===》根据url截图开始！");
//        String resultFileName = screenshot(path, loadTime, resourceId);
//        log.info(Thread.currentThread().getName() + "===》根据url截图结束！");
////        repo.update(qBmMarket).set(qBmMarket.pictureUrl, resultFileName).where(qBmMarket.id.eq(id)).execute();
//    }

    @Async
    public void generator(String path, long loadTime, String resourceId, String token) {
        // 保证每步串行执行
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        Future<String> submit = executorService.submit(() -> screenshot(path, loadTime, resourceId, token));
        try {
            String resultFileName = submit.get();
            extPanelGroupMapper.updatePictureUrl(resultFileName, resourceId);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            executorService.shutdown();
        }
//        String resultFileName = screenshot(path, loadTime, resourceId, token);
//        extPanelGroupMapper.updatePictureUrl(resultFileName, resourceId);
    }

    /**
     * 根据url截图
     *
     * @param path
     * @param loadTime
     * @param id
     * @return
     */
    public String screenshot(String path, long loadTime, String id, String token) {
        System.setProperty(ChromeDriverService.CHROME_DRIVER_SILENT_OUTPUT_PROPERTY, "true");
        System.setProperty("webdriver.chrome.driver", driverPath);
        ChromeOptions chromeOptions = new ChromeOptions();
        chromeOptions.addArguments("--headless");
        chromeOptions.addArguments("--no-sandbox");
        chromeOptions.addArguments("--disable-dev-shm-usage");
        chromeOptions.addArguments("--remote-debugging-port=9222");
        WebDriver webDriver = new ChromeDriver(chromeOptions);
        webDriver.manage().window().setSize(new Dimension(1920, 1080));
//        webDriver.manage().window().maximize();
        webDriver.manage().timeouts().pageLoadTimeout(loadTime + 20, TimeUnit.SECONDS);
        String resultFileName = "panelGroup_" + id + ".jpg";
        String resultFilePath = uploadPath + "/" + resultFileName;
        log.info("开始截图-------->");
        log.info("所需token:{}", token);
        try {
            String concatUrl =  path + "/" + token;
            log.info("截图地址拼接前: ", concatUrl);

            // 先访问链接，再设置cookie
            webDriver.get(concatUrl);
            if (StringUtils.isNotEmpty(token)) {
                webDriver.manage().deleteAllCookies();
                // 添加cookie，跳过认证从而实现截图
                Cookie cookie = new Cookie("Authorization", token);
                webDriver.manage().addCookie(cookie);
                webDriver.navigate().refresh();
            }

            ThreadUtil.sleep(loadTime * 1000);
            log.info("selenium模拟网页的所有cookie: ", JSONUtil.toJsonStr(webDriver.manage().getCookies()));
            File srcFile = ((TakesScreenshot) webDriver).getScreenshotAs(OutputType.FILE);
            FileUtil.copy(srcFile, new File(resultFilePath), true);

            log.info("结束截图-------->");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            webDriver.quit();
        }
        return pictureViewPath + resultFileName;
    }
}
