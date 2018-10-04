#include "stdafx.h"
#include "easy_file.h"
using namespace std;

enum diff_options {
	diffNone = 0x0,
	diffOld = 0x1,
	diffNew = 0x2,
	diffRec = 0x4,
	diffWcs = 0x8,
	diffOutput = 0x40000000,
	diffHelp = 0x80000000,
};

const struct { const wchar_t* arg; const wchar_t* arg_alt; const wchar_t* params_desc; const wchar_t* description; const diff_options options; } cmd_options[] = {
	{ L"?",		L"help",			nullptr,		L"show this help",						diffHelp },
	{ L"n",		L"new",				L"<filename>",	L"specify new file(s)",					diffNew },
	{ L"o",		L"old",				L"<filename>",	L"specify old file(s)",					diffOld },
	{ L"r",		L"recursive",		nullptr,		L"search folder recursively",			diffRec },
	{ nullptr,	L"wcs",				nullptr,		L"folder is Windows Component Store",	diffWcs },
	{ L"O",		L"out",				L"<filename>",	L"output to file",						diffOutput },
};

void print_usage() {
	printf_s("\tUsage: expdiff [options]\n\n");
	for (auto o = begin(cmd_options); o != end(cmd_options); ++o) {
		if (o->arg != nullptr) printf_s("\t-%S", o->arg); else printf_s("\t");

		int len = 0;
		if (o->arg_alt != nullptr) {
			len = wcslen(o->arg_alt);
			printf_s("\t--%S", o->arg_alt);
		} else printf_s("\t");

		if (len < 6) printf_s("\t");

		if (o->params_desc != nullptr) len += printf_s(" %S", o->params_desc);

		if (len < 14) printf_s("\t");

		printf_s("\t: %S\n", o->description);
	}
}

set<string> load_exports(const wstring& file);

int wmain(int argc, wchar_t* argv[])
{
	int options = diffNone;
	const wchar_t* err_arg = nullptr;
	wstring new_files_pattern, old_files_pattern, output_file;

	printf_s("\n ExpDiff v0.2 https://github.com/WalkingCat/ExpDiff\n\n");

	for (int i = 1; i < argc; ++i) {
		const wchar_t* arg = argv[i];
		if ((arg[0] == '-') || ((arg[0] == '/'))) {
			diff_options curent_option = diffNone;
			if ((arg[0] == '-') && (arg[1] == '-')) {
				for (auto o = begin(cmd_options); o != end(cmd_options); ++o) {
					if ((o->arg_alt != nullptr) && (wcscmp(arg + 2, o->arg_alt) == 0)) { curent_option = o->options; }
				}
			} else {
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
				} else if (curent_option == diffOld) {
					if ((i + 1) < argc) old_files_pattern = argv[++i];
					else valid = false;
				} else if (curent_option == diffOutput) {
					if ((i + 1) < argc) output_file = argv[++i];
					else valid = false;
				} else options = (options | curent_option);
			}
			if (!valid && (err_arg == nullptr)) err_arg = arg;
		} else { if (new_files_pattern.empty()) new_files_pattern = arg; else err_arg = arg; }
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
		printf_s("can't open %ls for output\n", output_file.c_str());
		return 0;
	}

	auto search_files = [&](bool is_new) -> map<wstring, map<wstring, wstring>> {
		map<wstring, map<wstring, wstring>> ret;
		const auto& files_pattern = is_new ? new_files_pattern : old_files_pattern;
		fwprintf_s(out, L" %ls files: %ls", is_new ? L"new" : L"old", files_pattern.c_str());
		if (((options & diffWcs) == diffWcs)) {
			ret = find_files_wcs_ex(files_pattern);
		} else {
			ret = find_files_ex(files_pattern, (options & diffRec) == diffRec);
		}
		fwprintf_s(out, L"%ls\n", !ret.empty() ? L"" : L" (EMPTY!)");
		return ret;
	};

	map<wstring, map<wstring, wstring>> new_file_groups = search_files(true), old_file_groups = search_files(false);
	fwprintf_s(out, L"\n");
	if (new_file_groups.empty() && old_file_groups.empty()) return 0;

	if (((options & diffWcs) == 0)) {
		auto& new_files = new_file_groups[wstring()], &old_files = old_file_groups[wstring()];
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
	}

	fwprintf_s(out, L" diff legends: +: added, -: removed, *: changed, $: changed (original)\n");

	const map<wstring, wstring> empty_files;
	diff_maps(new_file_groups, old_file_groups,
		[&](const wstring& group_name, const map<wstring, wstring>* new_files, const map<wstring, wstring>* old_files) {
			bool printed_group_name = false;
			wchar_t printed_group_prefix = L' ';
			auto print_group_name = [&](const wchar_t prefix) {
				if (!printed_group_name) {
					fwprintf_s(out, L"\n %lc %ls (\n", prefix, group_name.c_str());
					printed_group_name = true;
					printed_group_prefix = prefix;
				}
			};

			bool printed_previous_file_name = false;
			diff_maps(new_files ? *new_files : empty_files, old_files ? *old_files : empty_files,
				[&](const wstring& file_name, const wstring * new_file, const wstring * old_file) {
					bool printed_file_name = false;
					auto print_file_name = [&](const wchar_t prefix) {
						if (!printed_file_name) {
							print_group_name(new_files ? old_files ? L'*' : L'+' : L'-');
							if (printed_previous_file_name) {
								fwprintf_s(out, L"\n");
							}
							fwprintf_s(out, L"   %lc %ls\n", prefix, file_name.c_str());
							printed_previous_file_name = printed_file_name = true;
						}
					};

					if (new_file == nullptr) {
						print_file_name('-');
						return;
					}

					if (old_file == nullptr) {
						print_file_name('+');
					}

					diff_sets(load_exports(*new_file), (old_file != nullptr) ? load_exports(*old_file) : set<string>(),
						[&](const string* new_str, const string* old_str) {
							print_file_name('*');
							if (new_str) {
								fprintf_s(out, "     + %s\n", new_str->c_str());
							} else if (old_str) {
								fprintf_s(out, "     - %s\n", old_str->c_str());
							}
						}
					);
				}
			);

			if (printed_group_name)
				fwprintf_s(out, L" %lc )\n", printed_group_prefix);
		}
	);

	fwprintf_s(out, L"\n");

	return 0;
}

set<string> load_exports(const wstring & filename)
{
	set<string> ret;

	[&]() {
		easy_file file(filename.c_str(), L"rb");
		if (!file.valid()) return;

		IMAGE_DOS_HEADER dos_header = {};
		if (!file.read(&dos_header)) return;
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
		} else if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
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