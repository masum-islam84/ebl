package org.dcsa.ctk.ebl.config;

import lombok.Data;
import org.dcsa.ctk.ebl.service.exception.StorageException;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Data
@Configuration
@Component
@ConfigurationProperties("app")
public class AppProperty {
    public static String RESOURCE_FILENAME = "application.properties";
    // TNT API keys
    private static final String UPLOAD_CONFIG_PATH_NAME_KEY = "app.upload_config_path";
    private String upload_config_path;

    public static String UPLOAD_CONFIG_PATH;
    public static Path uploadPath;
    public static boolean isAppDataUploaded = false;

    public void init(){
        AppProperty.UPLOAD_CONFIG_PATH = upload_config_path;
        makeUploadPath();
        isAppDataUploaded = true;
    }
 private static void makeUploadPath(){
        uploadPath = Paths.get(AppProperty.UPLOAD_CONFIG_PATH);
        try {
            Files.createDirectories(uploadPath);
        }
        catch (IOException e) {
            throw new StorageException("Could not initialize storage", e);
        }
    }

}
