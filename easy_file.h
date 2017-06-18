#pragma once

class easy_file {
	FILE* file;
public:
	easy_file(const wchar_t* path, const wchar_t* mode) : file(nullptr) { _wfopen_s(&file, path, mode); }
	easy_file(easy_file&& that) : file(that.file) { that.file = nullptr; }
	~easy_file() { if (file != nullptr) fclose(file); }

	bool valid() { return file != nullptr; }
	bool end() { return feof(file) != 0; }

	long offset() { return ftell(file); }
	bool reset(long offset) { return fseek(file, offset, SEEK_SET) == 0; }

	bool skip(long bytes) { return fseek(file, bytes, SEEK_CUR) == 0; }
	bool read(void* buffer, size_t size, size_t bytes) { return fread_s(buffer, size, 1, bytes, file) == bytes; }
	bool read(void* buffer, size_t size) { return read(buffer, size, size); }
	template<typename T> bool read(T* buffer) { return read(buffer, sizeof(T)); }
};