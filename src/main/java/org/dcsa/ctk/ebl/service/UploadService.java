package org.dcsa.ctk.ebl.service;

import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Path;

public interface UploadService {
	void store(MultipartFile file, Path uploadPath);
}
