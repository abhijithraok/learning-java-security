package com.abhijith.cryptography.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Logger;

public class PropertyUtil {
    private static final Properties properties = new Properties();
    private static final Logger logger = Logger.getLogger(PropertyUtil.class.getName());

    static {
        loadDefaultProperties();
    }

    private static void loadDefaultProperties() {
        InputStream inputStream = PropertyUtil.class.getClassLoader().getResourceAsStream("DefaultAlgorithm.properties");
        try {
            properties.load(inputStream);
            logger.info("Properties are loaded!!");
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static String getProperty(String key) {
        return properties.getProperty(key);
    }
}


