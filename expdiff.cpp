#include "stdafx.h"
#include "easy_file.h"
using namespace std;

enum diff_options {
	diffNone = 0x0,
	diffOld = 0x1,
	diffNew = 0x2,
	diffOutput = 0x40000000,
	diffHelp = 0x80000000,
};

const struct { const wchar_t* arg; const wchar_t* arg_alt; const wchar_t* params_desc; const wchar_t* description; const diff_options options; } cmd_options[] = {
	{ L"?",		L"help",			nullptr,		L"show this help",						diffHelp },
	{ L"n",		L"new",				L"<filename>",	L"specify new file(s)",					diffNew },
	{ L"o",		L"old",				L"<filename>",	L"specify old file(s)",					diffOld },
	{ nullptr,	L"out",				L"<filename>",	L"output to file",						diffOutput },
};

void print_usage() {
	printf_s("\tUsage: expdiff [options]\n\n");
	for (auto o = begin(cmd_options); o != end(cmd_options); ++o) {
		if (o->arg != nullptr) printf_s("\t-%S", o->arg); else printf_s("\t");

		int len = 0;
		if (o->arg_alt != nullptr) {
			len = wcslen(o->arg_alt);
			printf_s("\t--%S", o->arg_alt);
		}
		else printf_s("\t");

		if (len < 6) printf_s("\t");

		if (o->params_desc != nullptr) len += printf_s(" %S", o->params_desc);

		if (len < 14) printf_s("\t");

		printf_s("\t: %S\n", o->description);
	}
}

map<wstring, wstring> find_files(const wchar_t* pattern);
set<string> load_exports(const wstring& file);
template<typename TKey, typename TValue, typename TFunc> void diff_maps(const map<TKey, TValue>& new_map, const map<TKey, TValue>& old_map, TFunc& func);
template<typename TValue, typename TFunc> void diff_sets(const set<TValue>& new_set, const set<TValue>& old_set, TFunc& func);

int wmain(int argc, wchar_t* argv[])
{
	int options = diffNone;
	const wchar_t* err_arg = nullptr;
	wstring new_files_pattern, old_files_pattern, output_file;

	printf_s("\n ExpDiff v0.1 https://github.com/WalkingCat/ExpDiff\n\n");

	for (int i = 1; i < argc; ++i) {
		const wchar_t* arg = argv[i];
		if ((arg[0] == '-') || ((arg[0] == '/'))) {
			diff_options curent_option = diffNone;
			if ((arg[0] == '-') && (arg[1] == '-')) {
				for (auto o = begin(cmd_options); o != end(cmd_options); ++o) {
					if ((o->arg_alt != nullptr) && (wcscmp(arg + 2, o->arg_alt) == 0)) { curent_option = o->options; }
				}
			}
			else {
				for (auto o = begin(cmd_options); o != end(cmd_options); ++o) {
					if ((o->arg != nullptr) && (wcscmp(arg + 1, o->arg) == 0)) { curent_option = o->options; }
				}
			}

			bool valid = false;
			if (curent_option != diffNone) {
				valid = true;
				if (curent_option == diffNew) {
					if ((i + 1) < argc) new_files_pattern = argv[++i];
					else valid = false;
				}
				else if (curent_option == diffOld) {
					if ((i + 1) < argc) old_files_pattern = argv[++i];
					else valid = false;
				}
				else if (curent_option == diffOutput) {
					if ((i + 1) < argc) output_file = argv[++i];
					else valid = false;
				} else options = (options | curent_option);
			}
			if (!valid && (err_arg == nullptr)) err_arg = arg;
		}
		else { if (new_files_pattern.empty()) new_files_pattern = arg; else err_arg = arg; }
	}

	if ((new_files_pattern.empty() && old_files_pattern.empty()) || (err_arg != nullptr) || (options & diffHelp)) {
		if (err_arg != nullptr) printf_s("\tError in option: %S\n\n", err_arg);
		print_usage();
		return 0;
	}

	auto out = stdout;
	if (!output_file.empty()) {
		out = nullptr;
		_wfopen_s(&out, output_file.c_str(), L"w, ccs=UTF-8");
	}

	if (out == nullptr) {
		printf_s("can't open %ws for output\n", output_file.c_str());
		return 0;
	}

	auto new_files = find_files(new_files_pattern.c_str());
	auto old_files = find_files(old_files_pattern.c_str());

	fwprintf_s(out, L" new files: %ws%ws\n", new_files_pattern.c_str(), !new_files.empty() ? L"" : L" (NOT EXISTS!)");
	fwprintf_s(out, L" old files: %ws%ws\n", old_files_pattern.c_str(), !old_files.empty() ? L"" : L" (NOT EXISTS!)");

	fwprintf_s(out, L"\n");

	if (new_files.empty() & old_files.empty()) return 0; // at least one of them must exists

	if ((new_files.size() == 1) && (old_files.size() == 1)) {
		// allows diff single files with different names
		auto& new_file_name = new_files.begin()->first;
		auto& old_file_name = old_files.begin()->first;
		if (new_file_name != old_file_name) {
			auto diff_file_names = new_file_name + L" <=> " + old_file_name;
			auto new_file = new_files.begin()->second;
			new_files.clear();
			new_files[diff_file_names] = new_file;
			auto old_file = old_files.begin()->second;
			old_files.clear();
			old_files[diff_file_names] = old_file;
		}
	}

	fwprintf_s(out, L" diff legends: +: added, -: removed, *: changed, $: changed (original)\n");

	diff_maps(new_files, old_files, [&](const wstring& file_name, const wstring * new_file, const wstring * old_file) {
		if (new_file == nullptr) {
			fwprintf_s(out, L"\n- FILE: %ws\n", file_name.c_str());
			return;
		}
		bool printed_file_name = false;
		diff_sets(load_exports(*new_file), (old_file != nullptr) ? load_exports(*old_file) : set<string>(), [&](const string* new_str, const string* old_str) {
			if (!printed_file_name) {
				fwprintf_s(out, L"\n%ws FILE: %ws\n", (old_file == nullptr) ? L"+" : L"*", file_name.c_str());
				printed_file_name = true;
			}
			if (new_str) {
				fprintf_s(out, "  + %s\n", new_str->c_str());
			} else if (old_str) {
				fprintf_s(out, "  - %s\n", old_str->c_str());
			}
		});
	});

    return 0;
}

map<wstring, wstring> find_files(const wchar_t * pattern)
{
	map<wstring, wstring> ret;
	wchar_t path[MAX_PATH] = {};
	wcscpy_s(path, pattern);
	WIN32_FIND_DATA fd;
	HANDLE find = ::FindFirstFile(pattern, &fd);
	if (find != INVALID_HANDLE_VALUE) {
		do {
			if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
				PathRemoveFileSpec(path);
				PathCombine(path, path, fd.cFileName);
				ret[fd.cFileName] = path;
			}
		} while (::FindNextFile(find, &fd));
		::FindClose(find);
	}
	return ret;
}

set<string> load_exports(const wstring & filename)
{
	set<string> ret;

	[&]() {
		easy_file file(filename.c_str(), L"rb");
		if (!file.valid()) return;

		IMAGE_DOS_HEADER dos_header = {};
		if(!file.read(&dos_header)) return;
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return;
		if (!file.reset(dos_header.e_lfanew)) return;
		DWORD nt_sig = {};
		if (!file.read(&nt_sig)) return;
		if (nt_sig != IMAGE_NT_SIGNATURE) return;

		IMAGE_FILE_HEADER file_header = {};
		if (!file.read(&file_header)) return;

		WORD opt_magic = {};
		if (!file.read(&opt_magic)) return;
		if (!file.skip(-(long)sizeof(opt_magic))) return;

		DWORD export_dir_address = 0;
		DWORD export_dir_size = 0;
		if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			IMAGE_OPTIONAL_HEADER32 opt_header = {};
			if (!file.read(&opt_header)) return;
			export_dir_address = opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			export_dir_size = opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}
		else if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			IMAGE_OPTIONAL_HEADER64 opt_header = {};
			if (!file.read(&opt_header)) return;
			export_dir_address = opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			export_dir_size = opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}

		if (export_dir_address == 0) return;
		if (export_dir_size == 0) return;

		DWORD export_dir_offset = 0;
		for (WORD i = 0; i < file_header.NumberOfSections; ++i) {
			IMAGE_SECTION_HEADER section_header = {};
			if (!file.read(&section_header)) return;
			if ((export_dir_address >= section_header.VirtualAddress) && (export_dir_address <= (section_header.VirtualAddress + section_header.SizeOfRawData))) {
				export_dir_offset = export_dir_address - (section_header.VirtualAddress - section_header.PointerToRawData);
				break;
			}
		}

		//if (export_dir_offset == 0) return;

		if (!file.reset(export_dir_offset)) return;
		vector<BYTE> exports_dir(export_dir_size);
		if (!file.read(exports_dir.data(), exports_dir.size())) return;
		auto exports = (PIMAGE_EXPORT_DIRECTORY)exports_dir.data();

		for (DWORD i = 0; i < exports->NumberOfNames; i++) {
			DWORD name_addr = *((DWORD*)(exports_dir.data() + (exports->AddressOfNames - export_dir_address)) + i);
			auto name = (char*)exports_dir.data() + (name_addr - export_dir_address);
			char undname[4096] = {};
			if (UnDecorateSymbolName(name, undname, _countof(undname), UNDNAME_COMPLETE) > 0) {
				ret.emplace(undname);
			} else {
				ret.emplace(name);
			}
		}
	}();

	return ret;
}

template<typename TValue, typename TFunc>
void diff_sets(const set<TValue>& new_set, const set<TValue>& old_set, TFunc& func)
{
	auto new_it = new_set.begin();
	auto old_it = old_set.begin();
	
	while ((new_it != new_set.end()) || (old_it != old_set.end())) {
		int diff = 0;
		if (new_it != new_set.end()) {
			if (old_it != old_set.end()) {
				if (*new_it > *old_it) {
					diff = -1;
				} else if (*new_it < *old_it) {
					diff = 1;
				}
			} else diff = 1;
		} else {
			if (old_it != old_set.end())
				diff = -1;
		}

		if (diff > 0) {
			func(&*new_it, nullptr);
			++new_it;
		} else if (diff < 0) {
			func(nullptr, &*old_it);
			++old_it;
		} else {
			++new_it;
			++old_it;
		}
	}
}

template<typename TKey, typename TValue, typename TFunc>
void diff_maps(const map<TKey, TValue>& new_map, const map<TKey, TValue>& old_map, TFunc& func)
{
	auto new_it = new_map.begin();
	auto old_it = old_map.begin();

	while ((new_it != new_map.end()) || (old_it != old_map.end())) {
		int diff = 0;
		if (new_it != new_map.end()) {
			if (old_it != old_map.end()) {
				if (new_it->first > old_it->first) {
					diff = -1;
				} else if (new_it->first < old_it->first) {
					diff = 1;
				}
			} else diff = 1;
		} else {
			if (old_it != old_map.end())
				diff = -1;
		}

		if (diff > 0) {
			func(new_it->first, &new_it->second, nullptr);
			++new_it;
		} else if (diff < 0) {
			func(old_it->first, nullptr, &old_it->second);
			++old_it;
		} else {
			func(old_it->first, &new_it->second, &old_it->second);
			++new_it;
			++old_it;
		}
	}
}
