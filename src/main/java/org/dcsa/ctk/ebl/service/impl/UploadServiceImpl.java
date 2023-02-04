package org.dcsa.ctk.ebl.service.impl;

import lombok.extern.java.Log;
import org.dcsa.ctk.ebl.config.AppProperty;
import org.dcsa.ctk.ebl.service.UploadService;
import org.dcsa.ctk.ebl.service.exception.StorageException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Objects;

@Log
@Service
public class UploadServiceImpl implements UploadService {
	public void store(MultipartFile file, Path uploadPath) {
		try {
			if (file.isEmpty() || uploadPath == null) {
				throw new StorageException("Failed to store empty file for path.");
			}
			Path destinationFile = AppProperty.uploadPath.resolve(
					Paths.get(Objects.requireNonNull(file.getOriginalFilename())))
					.normalize().toAbsolutePath();
			if (!destinationFile.getParent().equals(AppProperty.uploadPath.toAbsolutePath())) {
				throw new StorageException(
						"Cannot store file outside current directory.");
			}
			try (InputStream inputStream = file.getInputStream()) {
				Files.copy(inputStream, destinationFile,
					StandardCopyOption.REPLACE_EXISTING);
			}
		}
		catch (IOException e) {
			throw new StorageException("Failed to store file.", e);
		}
	}
}
