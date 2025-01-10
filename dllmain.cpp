#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <help.h>
#include <name.hpp>
#include "cvinfo.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define CHECK_SYMBOL_PTR

#ifdef CHECK_SYMBOL_PTR
bool is_bad_ptr(void * p)
{
	MEMORY_BASIC_INFORMATION mbi = {0};
	if (::VirtualQuery(p, &mbi, sizeof(mbi))) {
		DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		bool b = !(mbi.Protect & mask);
		// check if the page is not a guard page
		if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
			b = true;
		}
		return b;
	}
	return true;
}
#endif

unsigned long crc_table[256] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d };

unsigned long CRC_MS(const unsigned char* data, unsigned long length, unsigned long crc)
{
	while (length-- != 0)
		crc = (crc >> 8) ^ crc_table[(crc & 0xFF) ^ *data++];

	return crc;
}

enum FeatureEnum
{
	SafeSEH = 0x1,
	UsesClr = 0x2,
	ClrSafe = 0x4,
	SupportsWinRT = 0x8,
	Report_Dev11 = 0x10,
	C_CppModule = 0x80,
	SecurityCheck = 0x100,
	SDL = 0x200,
	ControlFlowGuard = 0x400,
	ControlFlowGuard2 = 0x800,
	GuardEHandler = 0x1000,
	MPXEnabled = 0x2000,
	OneModuleEnablesGuardEHCont = 0x4000,
	UseSPD = 0x8000,
	Unknown3 = 0x10000,
	RTTIReportingIgnoreDisabled = 0x20000,
	CompileTargetsKernel = 0x40000000,
	KernelAware = 0x80000000,
};
enum CompileType
{
	COMPILE_ASM = 0x103,
	COMPILE_C = 0x104,
	COMPILE_CPP = 0x105,
	COMPILE_C_CVTCIL = 0x106,
	COMPILE_CPP_CVTCIL = 0x107,
	COMPILE_C_LTCG = 0x108,
	COMPILE_CPP_LTCG = 0x109,
	COMPILE_MSIL = 0x10A,
	COMPILE_C_PGOINSTRUMENT = 0x10B,
	COMPILE_CPP_PGOINSTRUMENT = 0x10C,
	COMPILE_C_PGOUSE = 0x10D,
	COMPILE_CPP_PGOUSE = 0x10E,
};
struct Symbol;
struct SymbolTableEntry
{
	IMAGE_SYMBOL symbol;
	IMAGE_AUX_SYMBOL aux;
};
struct RelocationEntry
{
	ea_t Rva;
	Symbol* Symbol;
	unsigned short Type;
	RelocationEntry() : Rva(0), Symbol(0), Type(IMAGE_REL_I386_DIR32)
	{
	}
	bool operator== (const RelocationEntry& src) = delete;
	bool operator!= (const RelocationEntry& src) = delete;
};
struct Symbol
{
	qstring Name;
	ea_t Address;
	ssize_t Size;
	ea_t Offset;
	bool IsExtern;
	bool IsLocal;
	bool IsData;
	unsigned char* Data;
	qvector<RelocationEntry> Relocations;
	int SectionNumber;
	int SectionSymbolNumber;
	int EntrySymbolNumber;
	Symbol() : Address(0), Size(0), Offset(0), IsExtern(false), IsLocal(false), IsData(false), Data(0), SectionNumber(0), SectionSymbolNumber(0), EntrySymbolNumber(0)
	{
	}
	bool operator==(const Symbol& that) = delete;
	bool operator!=(const Symbol& that) = delete;
};

#define UNLINK_NAME "Unlink"
#define UNLINK_FUNC_NAME "UnlinkFunc"
#define UNLINK_EXTERN_NAME "Unlink Extern"
#define UNLINK_EXPORT_NAME "Export Unlinked Modules"

ea_t func_start;
ea_t func_end;
void idaapi get_func_chunks(ea_t ea1, ea_t ea2, void* ud)
{
	func_start = ea1;
	func_end = ea2;
}

struct unlink_entry
{
	ea_t ea;
	unsigned int module_index;
	bool is_extern;
	bool is_local;
};

bool operator== (const unlink_entry& u1, const unlink_entry& u2)
{
	return u1.ea == u2.ea && u1.module_index == u2.module_index;
}

qvector<qstring> modules;
qvector<unlink_entry> entries;

struct module_chooser_t : public chooser_t
{
protected:
	static const int widths_[];
	static const char* const header_[];

public:
	// this chooser is embedded into the modal form
	module_chooser_t();

	virtual size_t idaapi get_count() const override { return modules.size(); }
	virtual void idaapi get_row(
		qstrvec_t* cols,
		int* icon_,
		chooser_item_attrs_t* attrs,
		size_t n) const override;
};

const int module_chooser_t::widths_[] = { 40 };
const char* const module_chooser_t::header_[] = { "Module" };

inline module_chooser_t::module_chooser_t()
	: chooser_t(CH_KEEP,
		qnumber(widths_), widths_, header_)
{
	CASSERT(qnumber(widths_) == qnumber(header_));
}

void idaapi module_chooser_t::get_row(
	qstrvec_t* cols_,
	int* icon_,
	chooser_item_attrs_t*,
	size_t n) const
{
	qstrvec_t& cols = *cols_;
	cols[0] = modules[n];
	CASSERT(qnumber(header_) == 1);
	*icon_ = 150;
}

struct entry_chooser_t : public chooser_t
{
protected:
	static const int widths_[];
	static const char* const header_[];

public:
	// this chooser is embedded into the modal form
	entry_chooser_t();

	virtual size_t idaapi get_count() const override { return entries.size(); }
	virtual void idaapi get_row(
		qstrvec_t* cols,
		int* icon_,
		chooser_item_attrs_t* attrs,
		size_t n) const override;
	virtual cbret_t idaapi enter(size_t n) override
	{
		jumpto(entries[n].ea);
		return cbret_t();
	}

	virtual cbret_t idaapi del(size_t n) override
	{
		entries.del(entries[n]);
		return adjust_last_item(n);
	}
};

const int entry_chooser_t::widths_[] = { 70, 20, 20, 20 };
const char* const entry_chooser_t::header_[] = { "Name", "Type", "Address", "Module" };

inline entry_chooser_t::entry_chooser_t()
	: chooser_t(CH_KEEP | CH_CAN_DEL,
		qnumber(widths_), widths_, header_, "Unlinker")
{
	CASSERT(qnumber(widths_) == qnumber(header_));
}

void idaapi entry_chooser_t::get_row(
	qstrvec_t* cols_,
	int* icon_,
	chooser_item_attrs_t* attrs,
	size_t n) const
{
	qstrvec_t& cols = *cols_;
	int ea = entries[n].ea;
	if (is_code(get_flags(ea)))
	{
		qstring func_name;
		if (get_func_name(&func_name, ea) > 0 && !entries[n].is_local)
		{
			cols[0] = func_name;
			size_t s = getinf(INF_SHORT_DEMNAMES);
			qstring str;
			if (demangle_name(&str, func_name.c_str(), s) > 0)
			{
				cols[0] = str;
			}
			if (entries[n].is_extern)
			{
				cols[1] = "Extern Function";
			}
			else
			{
				cols[1] = "Function";
			}
			cols[2].sprnt("%x", ea);
			cols[3] = modules[entries[n].module_index];
			func_t* func = get_func(ea);
			if (func)
			{
				attrs->color = func->color;
			}
		}
		else if (entries[n].is_local)
		{
			qstring data_name;
			if (get_name(&data_name, ea) > 0)
			{
				cols[0] = data_name;
				cols[1] = "Local Label";
				cols[2].sprnt("%x", ea);
				cols[3] = modules[entries[n].module_index];
			}
		}
	}
	else if (is_data(get_flags(ea)))
	{
		qstring data_name;
		if (get_name(&data_name, ea) > 0)
		{
			cols[0] = data_name;
			size_t s = getinf(INF_SHORT_DEMNAMES);
			qstring str;
			if (demangle_name(&str, data_name.c_str(), s) > 0)
			{
				cols[0] = str;
			}
			if (entries[n].is_extern)
			{
				cols[1] = "Extern Data";
			}
			else if (entries[n].is_local)
			{
				cols[1] = "Local Data";
			}
			else
			{
				cols[1] = "Data";
			}
			cols[2].sprnt("%x", ea);
			cols[3] = modules[entries[n].module_index];
		}
	}
	*icon_ = 35;
}

int button_callback(int button_code, form_actions_t& fa)
{
	static const char form[] =
		"STARTITEM 0\n"
		"Add Module\n\n"
		"<Module Name:q0:" QSTRINGIZE(QMAXPATH) ":30::>\n"
		"\n";

	qstring str;
	if (ask_form(form, &str))
	{
		modules.add(str);
		fa.refresh_field(0);
	}
	return 0;
}

int get_module()
{
	static const char form[] =
		"STARTITEM 0\n"
		"Select Module\n\n"
		"<Select Module:E0::30::>\n\n"
		"<Add Module:B1:30:::>\n"
		"\n";

	module_chooser_t chooser;
	sizevec_t sel;
	if (ask_form(form, &chooser, &sel, &button_callback) && sel.size())
	{
		return sel[0];
	}
	return -1;
}

void add_entry(unlink_entry e)
{
	auto entry = std::find_if(entries.begin(), entries.end(), [e](unlink_entry e2) {return e.ea == e2.ea && e.module_index == e2.module_index; });
	if (entry == entries.end())
	{
		entries.push_back(e);
		refresh_chooser("Unlinker");
	}
	else if (e.is_extern == false && entry->is_extern == true)
	{
		entries.erase(entry);
		entries.push_back(e);
		refresh_chooser("Unlinker");
	}
}

bool unlink_action(ea_t ea, int i)
{
	if (ea != BADADDR)
	{
		if (is_code(get_flags(ea)))
		{
			qstring func_name;
			if (get_func_name(&func_name, ea) > 0)
			{
				iterate_func_chunks(get_func(ea), get_func_chunks, nullptr);
				if (i == -1) {
					i = get_module();
				}
				if (i != -1)
				{
					unlink_entry e;
					e.ea = func_start;
					e.is_extern = false;
					e.is_local = false;
					e.module_index = i;
					int func_size = func_end - func_start;
					add_entry(e);
					insn_t insn;
					int insn_size = 0;
					for (ea_t k = func_start; k < func_start + func_size; k += insn_size)
					{
						flags_t _flags = get_flags(k);
						if (is_code(_flags) || is_align(_flags))
						{
							insn_size = decode_insn(&insn, k);
							for (int index = 0; index < 2; index++)
							{
								switch (insn.ops[index].type)
								{
								case o_mem:
								case o_displ:
									if (!is_numop(_flags, index))
									{
										if (is_code(get_flags(insn.ops[index].addr)))
										{
											qstring func_name2;
											if (get_func_name(&func_name2, insn.ops[index].addr) > 0)
											{
												unlink_entry e2;
												e2.ea = insn.ops[index].addr;
												e2.is_extern = (insn.ops[index].addr < func_start || insn.ops[index].addr > func_start + func_size);
												e2.is_local = (insn.ops[index].addr > func_start && insn.ops[index].addr < func_start + func_size);
												e2.module_index = i;
												add_entry(e2);
											}
										}
										else if (is_data(get_flags(insn.ops[index].addr)))
										{
											qstring data_name2;
											if (get_name(&data_name2, insn.ops[index].addr) > 0)
											{
												ea_t data_start = get_item_head(insn.ops[index].addr);
												unlink_entry e2;
												e2.ea = data_start;
												e2.is_extern = (insn.ops[index].addr < func_start || insn.ops[index].addr > func_start + func_size);
												e2.is_local = (insn.ops[index].addr > func_start && insn.ops[index].addr < func_start + func_size);
												e2.module_index = i;
												add_entry(e2);
											}
										}
									}
									break;
								case o_imm:
									if (!is_numop(_flags, index))
									{
										if (is_code(get_flags(insn.ops[index].value)))
										{
											qstring func_name2;
											if (get_func_name(&func_name2, insn.ops[index].value) > 0)
											{
												unlink_entry e2;
												e2.ea = insn.ops[index].value;
												e2.is_extern = (insn.ops[index].addr < func_start || insn.ops[index].addr > func_start + func_size);
												e2.is_local = (insn.ops[index].addr > func_start && insn.ops[index].addr < func_start + func_size);
												e2.module_index = i;
												add_entry(e2);
											}
										}
										else if (is_data(get_flags(insn.ops[index].value)))
										{
											qstring data_name2;
											if (get_name(&data_name2, insn.ops[index].value) > 0)
											{
												ea_t data_start = get_item_head(insn.ops[index].value);
												unlink_entry e2;
												e2.ea = data_start;
												e2.is_extern = (insn.ops[index].addr < func_start || insn.ops[index].addr > func_start + func_size);
												e2.is_local = (insn.ops[index].addr > func_start && insn.ops[index].addr < func_start + func_size);
												e2.module_index = i;
												add_entry(e2);
											}
										}
									}
									break;
								case o_near:
									if (insn.ops[index].dtype == dt_dword && (insn.ops[index].addr < func_start || insn.ops[index].addr > func_start + func_size))
									{
										if (is_code(get_flags(insn.ops[index].addr)))
										{
											qstring func_name2;
											if (get_func_name(&func_name2, insn.ops[index].addr) > 0)
											{
												unlink_entry e2;
												e2.ea = insn.ops[index].addr;
												e2.is_extern = true;
												e2.is_local = false;
												e2.module_index = i;
												add_entry(e2);
											}
										}
										else if (is_data(get_flags(insn.ops[index].addr)))
										{
											qstring data_name2;
											if (get_name(&data_name2, insn.ops[index].addr) > 0)
											{
												ea_t data_start = get_item_head(insn.ops[index].addr);
												unlink_entry e2;
												e2.ea = data_start;
												e2.is_extern = true;
												e2.is_local = false;
												e2.module_index = i;
												add_entry(e2);
											}
										}
									}
									break;
								}
							}
						}
						else
						{
							uint32 address = get_dword(k);
							
							if ((address > func_start && address < func_start + func_size))
							{
								unlink_entry e2;
								e2.ea = address;
								e2.is_extern = false;
								e2.is_local = true;
								e2.module_index = i;
								add_entry(e2);
							}

							insn_size = 4;
						}
					}
				}
			}
		}
		else if (is_data(get_flags(ea)))
		{
			qstring data_name;
			if (get_name(&data_name, ea) > 0)
			{
				ea_t data_start = get_item_head(ea);
				if (i == -1) {
					i = get_module();
				}
				if (i != -1)
				{
					unlink_entry e;
					e.ea = data_start;
					e.is_extern = false;
					e.is_local = false;
					e.module_index = i;
					add_entry(e);
				}
			}
		}
		return true;
	}
	return false;
}

struct ahandler_unlink_t : public action_handler_t
{
	virtual int idaapi activate(action_activation_ctx_t*) override
	{
		ea_t ea = get_screen_ea();
		unlink_action(ea, -1);
		return true;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*) override
	{
		return AST_ENABLE_ALWAYS;
	}
};
static ahandler_unlink_t ahandler_unlink;

struct ahandler_unlink_func_t : public action_handler_t
{
	virtual int idaapi activate(action_activation_ctx_t* ctx) override
	{
		int i = get_module();
		if (i != -1)
		{
			for (size_t x = 0, n = ctx->chooser_selection.size(); x < n; ++x)
			{
				func_t* func = getn_func(ctx->chooser_selection[x]);
				ea_t ea = func->start_ea;
				unlink_action(ea, i);
			}
		}

		return true;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*) override
	{
		return AST_ENABLE_ALWAYS;
	}
};
static ahandler_unlink_func_t ahandler_unlink_func;

struct ahandler_unlink_extern_t : public action_handler_t
{
	virtual int idaapi activate(action_activation_ctx_t*) override
	{
		ea_t ea = get_screen_ea();
		if (is_code(get_flags(ea)))
		{
			qstring func_name;
			if (get_func_name(&func_name, ea) > 0)
			{
				iterate_func_chunks(get_func(ea), get_func_chunks, nullptr);
				int i = get_module();
				if (i != -1)
				{
					unlink_entry e;
					e.ea = func_start;
					e.is_extern = true;
					e.is_local = false;
					e.module_index = i;
					add_entry(e);
				}
			}
		}
		else if (is_data(get_flags(ea)))
		{
			qstring data_name;
			if (get_name(&data_name, ea) > 0)
			{
				ea_t data_start = get_item_head(ea);
				int i = get_module();
				if (i != -1)
				{
					unlink_entry e;
					e.ea = data_start;
					e.is_extern = true;
					e.is_local = false;
					e.module_index = i;
					add_entry(e);
				}
			}
		}
		return true;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*) override
	{
		return AST_ENABLE_ALWAYS;
	}
};
static ahandler_unlink_extern_t ahandler_unlink_extern;

qvector<Symbol> CodeSymbols;
qvector<Symbol> RDataSymbols;
qvector<Symbol> DataSymbols;
qvector<Symbol> IDataSymbols;
qvector<Symbol> BSSSymbols;


bool IsSymbol(ea_t address)
{
	for (size_t i = 0; i < CodeSymbols.size(); i++)
	{
		size_t index = CodeSymbols.size() - i - 1;
		if (address >= CodeSymbols[index].Address && address < CodeSymbols[index].Address + CodeSymbols[index].Size)
		{
			return true;
		}
	}
	for (size_t i = 0; i < RDataSymbols.size(); i++)
	{
		if (address >= RDataSymbols[i].Address && address < RDataSymbols[i].Address + RDataSymbols[i].Size)
		{
			return true;
		}
	}
	for (size_t i = 0; i < DataSymbols.size(); i++)
	{
		if (address >= DataSymbols[i].Address && address < DataSymbols[i].Address + DataSymbols[i].Size)
		{
			return true;
		}
	}
	for (size_t i = 0; i < IDataSymbols.size(); i++)
	{
		if (address >= IDataSymbols[i].Address && address < IDataSymbols[i].Address + IDataSymbols[i].Size)
		{
			return true;
		}
	}
	for (size_t i = 0; i < BSSSymbols.size(); i++)
	{
		if (address >= BSSSymbols[i].Address && address < BSSSymbols[i].Address + BSSSymbols[i].Size)
		{
			return true;
		}
	}
	return false;
}

Symbol& FindSymbol(ea_t address, bool local = true)
{
	for (size_t i = 0; i < CodeSymbols.size(); i++)
	{
		size_t index = CodeSymbols.size() - i - 1;
		if (address >= CodeSymbols[index].Address && address < CodeSymbols[index].Address + CodeSymbols[index].Size)
		{
			if (local || !CodeSymbols[index].IsLocal)
			{
				return CodeSymbols[index];
			}
		}
	}
	for (size_t i = 0; i < RDataSymbols.size(); i++)
	{
		if (address >= RDataSymbols[i].Address && address < RDataSymbols[i].Address + RDataSymbols[i].Size)
		{
			return RDataSymbols[i];
		}
	}
	for (size_t i = 0; i < DataSymbols.size(); i++)
	{
		if (address >= DataSymbols[i].Address && address < DataSymbols[i].Address + DataSymbols[i].Size)
		{
			return DataSymbols[i];
		}
	}
	for (size_t i = 0; i < IDataSymbols.size(); i++)
	{
		if (address >= IDataSymbols[i].Address && address < IDataSymbols[i].Address + IDataSymbols[i].Size)
		{
			return IDataSymbols[i];
		}
	}
	for (size_t i = 0; i < BSSSymbols.size(); i++)
	{
		if (address >= BSSSymbols[i].Address && address < BSSSymbols[i].Address + BSSSymbols[i].Size)
		{
			return BSSSymbols[i];
		}
	}
	__assume(false);
}

void export_unlinked_module(qstring name, qvector<unlink_entry>& vector)
{
	CodeSymbols.clear();
	RDataSymbols.clear();
	DataSymbols.clear();
	IDataSymbols.clear();
	BSSSymbols.clear();
	qstring str = name;
	str += ".obj";
	char* path = ask_file(true, str.c_str(), "*.obj");
	if (path)
	{
		for (size_t i = 0; i < vector.size(); i++)
		{
			Symbol s;
			qstring segment;
			ea_t ea = vector[i].ea;
			get_segm_name(&segment, getseg(ea));
			if (segment == ".text" || segment == "BEGTEXT")
			{
				qstring func_name;
				if (get_func_name(&func_name, ea) > 0 && !vector[i].is_local)
				{
					iterate_func_chunks(get_func(ea), get_func_chunks, nullptr);
					s.Name = func_name;
					s.Address = ea;
					s.Size = func_end - func_start;
					s.Offset = 0;
					s.IsExtern = vector[i].is_extern;
					s.IsLocal = false;
					s.IsData = false;
					if (!s.IsExtern)
					{
						s.Data = new unsigned char[s.Size];
						get_bytes(s.Data, s.Size, s.Address);
					}
					else
					{
						s.Data = nullptr;
					}
					CodeSymbols.push_back(s);
				}
				else
				{
					qstring data_name;
					if (get_name(&data_name, ea) > 0)
					{
						s.Name = data_name;
						s.Address = ea;
						s.Offset = 0;
						s.Size = get_item_size(ea);
						s.IsExtern = vector[i].is_extern;
						s.IsLocal = vector[i].is_local;
						s.IsData = true;
						if (!s.IsExtern && !s.IsLocal)
						{
							s.Data = new unsigned char[s.Size];
							get_bytes(s.Data, s.Size, s.Address);
						}
						else
						{
							s.Data = nullptr;
						}
						CodeSymbols.push_back(s);
					}
				}
			}
			else if (segment == ".rdata")
			{
				qstring data_name;
				if (get_name(&data_name, ea) > 0)
				{
					s.Name = data_name;
					s.Address = ea;
					s.Size = get_item_size(ea);
					s.Offset = 0;
					s.IsExtern = vector[i].is_extern;
					s.IsLocal = false;
					s.IsData = true;
					if (!s.IsExtern)
					{
						s.Data = new unsigned char[s.Size];
						get_bytes(s.Data, s.Size, s.Address);
					}
					else
					{
						s.Data = nullptr;
					}
					RDataSymbols.push_back(s);
				}
			}
			else if (segment == ".data" || segment == "DGROUP")
			{
				qstring data_name;
				if (get_name(&data_name, ea) > 0)
				{
					s.Name = data_name;
					s.Address = ea;
					s.Size = get_item_size(ea);
					s.Offset = 0;
					s.IsExtern = vector[i].is_extern;
					s.IsLocal = false;
					s.IsData = true;
					if (!s.IsExtern)
					{
						if (is_loaded(s.Address))
						{
							s.Data = new unsigned char[s.Size];
							get_bytes(s.Data, s.Size, s.Address);
							DataSymbols.push_back(s);
						}
						else
						{
							s.Data = nullptr;
							BSSSymbols.push_back(s);
						}
					}
					else
					{
						s.Data = nullptr;
						DataSymbols.push_back(s);
					}
				}
			}
			else if (segment == ".idata")
			{
				qstring data_name;
				if (get_name(&data_name, ea) > 0)
				{
					s.Name = data_name;
					s.Address = ea;
					s.Size = get_item_size(ea);
					s.Offset = 0;
					s.IsExtern = true;
					s.IsLocal = false;
					s.IsData = true;
					s.Data = nullptr;
					IDataSymbols.push_back(s);
				}
			}
			else if (segment == ".bss")
			{
				qstring data_name;
				if (get_name(&data_name, ea) > 0)
				{
					s.Name = data_name;
					s.Address = ea;
					s.Size = get_item_size(ea);
					s.Offset = 0;
					s.IsExtern = vector[i].is_extern;
					s.IsLocal = false;
					s.IsData = true;
					if (!s.IsExtern && is_loaded(s.Address))
					{
						s.Data = new unsigned char[s.Size];
						get_bytes(s.Data, s.Size, s.Address);
					}
					else
					{
						s.Data = nullptr;
					}
					BSSSymbols.push_back(s);
				}
			}
		}
		for (size_t j = 0; j < CodeSymbols.size(); j++)
		{
			if (!CodeSymbols[j].IsExtern)
			{
				if (!CodeSymbols[j].IsLocal)
				{
					if (!CodeSymbols[j].IsData)
					{
						insn_t insn;
						int insn_size = 0;
						for (ea_t k = CodeSymbols[j].Address; k < CodeSymbols[j].Address + CodeSymbols[j].Size; k += insn_size)
						{
							int pos = k - CodeSymbols[j].Address;
							flags_t _flags = get_flags(k);
							if (is_code(_flags) || is_align(_flags))
							{
								insn_size = decode_insn(&insn, k);
								for (int index = 0; index < 2; index++)
								{
									switch (insn.ops[index].type)
									{
									case o_mem:
									case o_displ:
										if (!is_numop(_flags, index))
										{
											if (IsSymbol(insn.ops[index].addr))
											{
												Symbol& fsym = FindSymbol(insn.ops[index].addr);
												RelocationEntry r;
												r.Rva = pos + insn.ops[index].offb;
												r.Symbol = &fsym;
												unsigned int* data = (unsigned int*)(CodeSymbols[j].Data + pos + insn.ops[index].offb);
												unsigned int offset = insn.ops[index].addr - fsym.Address;
												*data = offset;
												CodeSymbols[j].Relocations.push_back(r);
											}
										}
										break;
									case o_imm:
										if (!is_numop(_flags, index))
										{
											if (IsSymbol(insn.ops[index].value))
											{
												Symbol& fsym = FindSymbol(insn.ops[index].value);
												RelocationEntry r;
												r.Rva = pos + insn.ops[index].offb;
												r.Symbol = &fsym;
												unsigned int* data = (unsigned int*)(CodeSymbols[j].Data + pos + insn.ops[index].offb);
												unsigned int offset = insn.ops[index].value - fsym.Address;
												*data = offset;
												CodeSymbols[j].Relocations.push_back(r);
											}
										}
										break;
									case o_near:
										if (insn.ops[index].dtype == dt_dword && (insn.ops[index].addr < CodeSymbols[j].Address || insn.ops[index].addr > CodeSymbols[j].Address + CodeSymbols[j].Size))
										{
											if (IsSymbol(insn.ops[index].addr))
											{
												Symbol& fsym = FindSymbol(insn.ops[index].addr);
												RelocationEntry r;
												r.Rva = pos + insn.ops[index].offb;
												r.Symbol = &fsym;
												r.Type = IMAGE_REL_I386_REL32;
												unsigned int* data = (unsigned int*)(CodeSymbols[j].Data + pos + insn.ops[index].offb);
												unsigned int offset = insn.ops[index].addr - fsym.Address;
												*data = offset;
												CodeSymbols[j].Relocations.push_back(r);
											}
										}
										break;
									}
								}
							}
							else
							{
								insn_size = 4;
								unsigned int* data = (unsigned int*)(CodeSymbols[j].Data + pos);
								#ifdef CHECK_SYMBOL_PTR
								if (is_bad_ptr(data)) {
									msg("unlinker --- 1 Invalid Address pos %x\n", (int)pos);
									continue;
								}
								#endif
								if (IsSymbol(*data))
								{
									Symbol& fsym = FindSymbol(*data);
									RelocationEntry r;
									r.Rva = pos;
									r.Symbol = &fsym;
									unsigned int offset = *data - fsym.Address;
									*data = offset;
									CodeSymbols[j].Relocations.push_back(r);
								}
							}
						}
					}
					else
					{
						for (ea_t k = CodeSymbols[j].Address; k < CodeSymbols[j].Address + CodeSymbols[j].Size; k += 4)
						{
							unsigned int* data = (unsigned int*)(CodeSymbols[j].Data + k);
							#ifdef CHECK_SYMBOL_PTR
							if (is_bad_ptr(data)) {
								msg("unlinker --- 2 Invalid  k %x\n", (int)k);
								continue;
							}
							#endif
							if (IsSymbol(*data))
							{
								Symbol& fsym = FindSymbol(*data);
								RelocationEntry r;
								r.Rva = k;
								r.Symbol = &fsym;
								unsigned int offset = *data - fsym.Address;
								*data = offset;
								CodeSymbols[j].Relocations.push_back(r);
							}
						}
					}
				}
				else
				{
					Symbol& psym = FindSymbol(CodeSymbols[j].Address, false);
					CodeSymbols[j].Offset = CodeSymbols[j].Address - psym.Address;
				}
			}
		}
		for (size_t j = 0; j < RDataSymbols.size(); j++)
		{
			if (!RDataSymbols[j].IsExtern && is_off0(get_flags(RDataSymbols[j].Address)))
			{
				for (ssize_t k = 0; k < RDataSymbols[j].Size; k += 4)
				{
					unsigned int* data = (unsigned int*)(RDataSymbols[j].Data + k);
					#ifdef CHECK_SYMBOL_PTR
					if (is_bad_ptr(data)) {
						msg("unlinker --- 3 Invalid Address k %x\n", (int)k);
						continue;
					}
					#endif
					if (IsSymbol(*data))
					{
						Symbol& fsym = FindSymbol(*data);
						RelocationEntry r;
						r.Rva = k;
						r.Symbol = &fsym;
						unsigned int offset = *data - fsym.Address;
						*data = offset;
						RDataSymbols[j].Relocations.push_back(r);
					}
				}
			}
		}
		for (size_t j = 0; j < DataSymbols.size(); j++)
		{
			if (!DataSymbols[j].IsExtern && is_off0(get_flags(DataSymbols[j].Address)) && DataSymbols[j].Data)
			{
				for (ssize_t k = 0; k < DataSymbols[j].Size; k += 4)
				{
					unsigned int* data = (unsigned int*)(DataSymbols[j].Data + k);
					#ifdef CHECK_SYMBOL_PTR
					if (is_bad_ptr(data)) {
						msg("unlinker --- 4 Invalid Address k %x\n", (int)k);
						continue;
					}
					#endif
					if (IsSymbol(*data))
					{
						Symbol& fsym = FindSymbol(*data);
						RelocationEntry r;
						r.Rva = k;
						r.Symbol = &fsym;
						unsigned int offset = *data - fsym.Address;
						*data = offset;
						DataSymbols[j].Relocations.push_back(r);
					}
				}
			}
		}
		int symbolcount = 0;
		int sectioncount = 0;
		int stringtablesize = 0;
		symbolcount++; //@comp.id
		symbolcount++; //@feat.00
		symbolcount++; //.debug$s
		sectioncount++; //.debug$s
		for (size_t i = 0; i < CodeSymbols.size(); i++)
		{
			symbolcount++;
			stringtablesize += CodeSymbols[i].Name.length();
			stringtablesize++;
			if (!CodeSymbols[i].IsExtern && !CodeSymbols[i].IsLocal)
			{
				symbolcount++;
				sectioncount++;
			}
		}
		for (size_t i = 0; i < RDataSymbols.size(); i++)
		{
			symbolcount++;
			stringtablesize += RDataSymbols[i].Name.length();
			stringtablesize++;
			if (!RDataSymbols[i].IsExtern)
			{
				symbolcount++;
				sectioncount++;
			}
		}
		for (size_t i = 0; i < DataSymbols.size(); i++)
		{
			symbolcount++;
			stringtablesize += DataSymbols[i].Name.length();
			stringtablesize++;
			if (!DataSymbols[i].IsExtern)
			{
				symbolcount++;
				sectioncount++;
			}
		}
		for (size_t i = 0; i < IDataSymbols.size(); i++)
		{
			symbolcount++;
			stringtablesize += IDataSymbols[i].Name.length();
			stringtablesize++;
			if (!IDataSymbols[i].IsExtern)
			{
				symbolcount++;
				sectioncount++;
			}
		}
		for (size_t i = 0; i < BSSSymbols.size(); i++)
		{
			symbolcount++;
			stringtablesize += BSSSymbols[i].Name.length();
			stringtablesize++;
			if (!BSSSymbols[i].IsExtern)
			{
				symbolcount++;
				sectioncount++;
			}
		}
		char OutputFull[MAX_PATH];
		_fullpath(OutputFull, path, MAX_PATH);
		const char* CompilerString = "Microsoft (R) Optimizing Compiler";
		int DebugSize = 0;
		int DebugSSymbolsSize = 0;
		DebugSize += 4; //CV_SIGNATURE_C13
		DebugSize += 4; //DEBUG_S_SYMBOLS
		DebugSize += 4; //size of DebugSSymbols
		DebugSize += sizeof(OBJNAMESYM);
		DebugSSymbolsSize += sizeof(OBJNAMESYM);
		DebugSize += strlen(OutputFull);
		DebugSSymbolsSize += strlen(OutputFull);
		DebugSize++;
		DebugSSymbolsSize++;
		DebugSize += sizeof(COMPILESYM3);
		DebugSSymbolsSize += sizeof(COMPILESYM3);
		DebugSize += strlen(CompilerString);
		DebugSSymbolsSize += strlen(CompilerString);
		DebugSize++;
		DebugSSymbolsSize++;
		DebugSize += (4 - (DebugSize % 4)) % 4;
		unsigned char* DebugSSection = new unsigned char[DebugSize];
		memset(DebugSSection, 0, DebugSize);
		unsigned char* DebugSSectionPos = DebugSSection;
		*((unsigned int*)DebugSSectionPos) = CV_SIGNATURE_C13;
		DebugSSectionPos += 4;
		*((unsigned int*)DebugSSectionPos) = DEBUG_S_SYMBOLS;
		DebugSSectionPos += 4;
		*((unsigned int*)DebugSSectionPos) = DebugSSymbolsSize;
		DebugSSectionPos += 4;
		OBJNAMESYM* obj = (OBJNAMESYM*)DebugSSectionPos;
		obj->reclen = (unsigned short)(strlen(OutputFull) + 1 + sizeof(OBJNAMESYM) - 2);
		obj->rectyp = S_OBJNAME;
		obj->signature = 0;
		DebugSSectionPos += sizeof(OBJNAMESYM);
		qstrncpy((char*)DebugSSectionPos, OutputFull, DebugSize);
		DebugSSectionPos += strlen(OutputFull);
		DebugSSectionPos++;
		COMPILESYM3* compile = (COMPILESYM3*)DebugSSectionPos;
		compile->reclen = (unsigned short)(strlen(CompilerString) + 1 + sizeof(COMPILESYM3) - 2);
		compile->rectyp = S_COMPILE3;
		compile->flags.iLanguage = CV_CFL_CXX;
		compile->flags.fNoDbgInfo = 1;
		compile->machine = (unsigned short)CV_CFL_PENTIUMIII;
		compile->verFEMajor = (unsigned short)19;
		compile->verFEMinor = (unsigned short)28;
		compile->verFEBuild = (unsigned short)29913;
		compile->verFEQFE = (unsigned short)0;
		compile->verMajor = (unsigned short)19;
		compile->verMinor = (unsigned short)28;
		compile->verBuild = (unsigned short)29913;
		compile->verQFE = (unsigned short)0;
		DebugSSectionPos += sizeof(COMPILESYM3);
		qstrncpy((char*)DebugSSectionPos, CompilerString, DebugSize);
		DebugSSectionPos += strlen(CompilerString);
		DebugSSectionPos++;
		unsigned int CurrentFilePos = 0;
		CurrentFilePos += sizeof(IMAGE_FILE_HEADER);
		IMAGE_FILE_HEADER FileHeader;
		FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
		FileHeader.NumberOfSections = (WORD)sectioncount;
		FileHeader.TimeDateStamp = (DWORD)time(NULL);
		FileHeader.PointerToSymbolTable = 0;
		FileHeader.NumberOfSymbols = symbolcount + sectioncount;
		FileHeader.SizeOfOptionalHeader = 0;
		FileHeader.Characteristics = 0;
		IMAGE_SECTION_HEADER* sections = new IMAGE_SECTION_HEADER[sectioncount];
		unsigned char** sectiondata = new unsigned char* [sectioncount];
		IMAGE_RELOCATION** sectionrelocations = new IMAGE_RELOCATION * [sectioncount];
		qvector<RelocationEntry>** sectionrelocsymbols = new qvector<RelocationEntry>*[sectioncount];
		CurrentFilePos += (sizeof(IMAGE_SECTION_HEADER) * sectioncount);
		SymbolTableEntry* symbols = new SymbolTableEntry[symbolcount];
		char* strings = new char[stringtablesize];
		char* strpos = strings;
		int stroffset = 4;
		int cursection = 0;
		int cursymbol = 0;
		int cursymnum = 1;
		int CompileType = COMPILE_CPP;
		int CompilerIDVersion = 29913;
		int FeatureEnum = Report_Dev11 | C_CppModule | Unknown3 | SafeSEH | KernelAware;
		memcpy(symbols[cursymbol].symbol.N.ShortName, "@comp.id", IMAGE_SIZEOF_SHORT_NAME);
		symbols[cursymbol].symbol.Value = (CompileType << 16) | CompilerIDVersion;
		symbols[cursymbol].symbol.SectionNumber = IMAGE_SYM_ABSOLUTE;
		symbols[cursymbol].symbol.Type = 0;
		symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
		symbols[cursymbol].symbol.NumberOfAuxSymbols = 0;
		cursymbol++;
		cursymnum++;
		memcpy(symbols[cursymbol].symbol.N.ShortName, "@feat.00", IMAGE_SIZEOF_SHORT_NAME);
		symbols[cursymbol].symbol.Value = FeatureEnum;
		symbols[cursymbol].symbol.SectionNumber = IMAGE_SYM_ABSOLUTE;
		symbols[cursymbol].symbol.Type = 0;
		symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
		symbols[cursymbol].symbol.NumberOfAuxSymbols = 0;
		cursymbol++;
		cursymnum++;
		memcpy(sections[cursection].Name, ".debug$S", IMAGE_SIZEOF_SHORT_NAME);
		sections[cursection].Misc.VirtualSize = 0;
		sections[cursection].VirtualAddress = 0;
		sections[cursection].SizeOfRawData = DebugSize;
		sections[cursection].PointerToRawData = CurrentFilePos;
		sections[cursection].PointerToRelocations = 0;
		sections[cursection].NumberOfRelocations = 0;
		sectionrelocations[cursection] = 0;
		sectionrelocsymbols[cursection] = 0;
		sections[cursection].PointerToLinenumbers = 0;
		sections[cursection].NumberOfLinenumbers = 0;
		sections[cursection].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ;
		sectiondata[cursection] = DebugSSection;
		cursection++;
		CurrentFilePos += DebugSize;
		memcpy(symbols[cursymbol].symbol.N.ShortName, ".debug$S", IMAGE_SIZEOF_SHORT_NAME);
		symbols[cursymbol].symbol.Value = 0;
		symbols[cursymbol].symbol.SectionNumber = (SHORT)cursection;
		symbols[cursymbol].symbol.Type = 0;
		symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
		symbols[cursymbol].symbol.NumberOfAuxSymbols = 1;
		symbols[cursymbol].aux.Section.Length = DebugSize;
		symbols[cursymbol].aux.Section.NumberOfRelocations = 0;
		symbols[cursymbol].aux.Section.NumberOfLinenumbers = 0;
		symbols[cursymbol].aux.Section.CheckSum = 0;
		symbols[cursymbol].aux.Section.Number = 0;
		symbols[cursymbol].aux.Section.Selection = 0;
		symbols[cursymbol].aux.Section.bReserved = 0;
		symbols[cursymbol].aux.Section.HighNumber = 0;
		cursymbol++;
		cursymnum++;
		for (size_t i = 0; i < DataSymbols.size(); i++)
		{
			if (!DataSymbols[i].IsExtern)
			{
				memcpy(sections[cursection].Name, ".data\0\0\0", IMAGE_SIZEOF_SHORT_NAME);
				sections[cursection].Misc.VirtualSize = 0;
				sections[cursection].VirtualAddress = 0;
				sections[cursection].SizeOfRawData = DataSymbols[i].Size;
				if (DataSymbols[i].Data)
				{
					sections[cursection].PointerToRawData = CurrentFilePos;
					CurrentFilePos += DataSymbols[i].Size;
					if (DataSymbols[i].Relocations.size())
					{
						sections[cursection].PointerToRelocations = CurrentFilePos;
						sections[cursection].NumberOfRelocations = (WORD)DataSymbols[i].Relocations.size();
						CurrentFilePos += DataSymbols[i].Relocations.size() * sizeof(IMAGE_RELOCATION);
						sectionrelocations[cursection] = new IMAGE_RELOCATION[DataSymbols[i].Relocations.size()];
						sectionrelocsymbols[cursection] = &DataSymbols[i].Relocations;
						for (size_t j = 0; j < DataSymbols[i].Relocations.size(); j++)
						{
							sectionrelocations[cursection][j].VirtualAddress = DataSymbols[i].Relocations[j].Rva;
							sectionrelocations[cursection][j].SymbolTableIndex = 0;
							sectionrelocations[cursection][j].Type = DataSymbols[i].Relocations[j].Type;
						}
					}
					else
					{
						sections[cursection].PointerToRelocations = 0;
						sections[cursection].NumberOfRelocations = 0;
						sectionrelocations[cursection] = 0;
						sectionrelocsymbols[cursection] = 0;
					}
				}
				else
				{
					sections[cursection].PointerToRawData = 0;
					sections[cursection].PointerToRelocations = 0;
					sections[cursection].NumberOfRelocations = 0;
					sectionrelocations[cursection] = 0;
					sectionrelocsymbols[cursection] = 0;
				}
				sections[cursection].PointerToLinenumbers = 0;
				sections[cursection].NumberOfLinenumbers = 0;
				sections[cursection].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
				if (DataSymbols[i].Data)
				{
					sectiondata[cursection] = DataSymbols[i].Data;
				}
				else
				{
					sectiondata[cursection] = 0;
				}
				cursection++;
				DataSymbols[i].SectionNumber = cursection;
				DataSymbols[i].SectionSymbolNumber = cursymnum;
				memcpy(symbols[cursymbol].symbol.N.ShortName, ".data\0\0\0", IMAGE_SIZEOF_SHORT_NAME);
				symbols[cursymbol].symbol.Value = 0;
				symbols[cursymbol].symbol.SectionNumber = (SHORT)cursection;
				symbols[cursymbol].symbol.Type = 0;
				symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
				symbols[cursymbol].symbol.NumberOfAuxSymbols = 1;
				symbols[cursymbol].aux.Section.Length = DataSymbols[i].Size;
				symbols[cursymbol].aux.Section.NumberOfRelocations = 0;
				symbols[cursymbol].aux.Section.NumberOfLinenumbers = 0;
				if (DataSymbols[i].Data)
				{
					symbols[cursymbol].aux.Section.CheckSum = CRC_MS(DataSymbols[i].Data, DataSymbols[i].Size, 0);
				}
				else
				{
					symbols[cursymbol].aux.Section.CheckSum = 0;
				}
				symbols[cursymbol].aux.Section.Number = 0;
				symbols[cursymbol].aux.Section.Selection = 0;
				symbols[cursymbol].aux.Section.bReserved = 0;
				symbols[cursymbol].aux.Section.HighNumber = 0;
				cursymbol++;
				cursymnum++;
				cursymnum++;
			}
		}
		for (size_t i = 0; i < DataSymbols.size(); i++)
		{
			DataSymbols[i].EntrySymbolNumber = cursymnum;
			symbols[cursymbol].symbol.N.Name.Short = 0;
			symbols[cursymbol].symbol.N.Name.Long = stroffset;
			symbols[cursymbol].symbol.Value = 0;
			symbols[cursymbol].symbol.SectionNumber = (SHORT)DataSymbols[i].SectionNumber;
			symbols[cursymbol].symbol.Type = 0;
			symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
			symbols[cursymbol].symbol.NumberOfAuxSymbols = 0;
			cursymbol++;
			cursymnum++;
			qstrncpy(strpos, DataSymbols[i].Name.c_str(), stringtablesize);
			strpos += DataSymbols[i].Name.length();
			strpos++;
			stroffset += DataSymbols[i].Name.length();
			stroffset++;
		}
		for (size_t i = 0; i < CodeSymbols.size(); i++)
		{
			if (!CodeSymbols[i].IsExtern)
			{
				if (!CodeSymbols[i].IsLocal)
				{
					memcpy(sections[cursection].Name, ".text", 8);
					sections[cursection].Misc.VirtualSize = 0;
					sections[cursection].VirtualAddress = 0;
					sections[cursection].SizeOfRawData = CodeSymbols[i].Size;
					sections[cursection].PointerToRawData = CurrentFilePos;
					CurrentFilePos += CodeSymbols[i].Size;
					if (CodeSymbols[i].Relocations.size())
					{
						sections[cursection].PointerToRelocations = CurrentFilePos;
						sections[cursection].NumberOfRelocations = (WORD)CodeSymbols[i].Relocations.size();
						CurrentFilePos += CodeSymbols[i].Relocations.size() * sizeof(IMAGE_RELOCATION);
						sectionrelocations[cursection] = new IMAGE_RELOCATION[CodeSymbols[i].Relocations.size()];
						sectionrelocsymbols[cursection] = &CodeSymbols[i].Relocations;
						for (size_t j = 0; j < CodeSymbols[i].Relocations.size(); j++)
						{
							sectionrelocations[cursection][j].VirtualAddress = CodeSymbols[i].Relocations[j].Rva;
							sectionrelocations[cursection][j].SymbolTableIndex = 0;
							sectionrelocations[cursection][j].Type = CodeSymbols[i].Relocations[j].Type;
						}
					}
					else
					{
						sections[cursection].PointerToRelocations = 0;
						sections[cursection].NumberOfRelocations = 0;
						sectionrelocations[cursection] = 0;
						sectionrelocsymbols[cursection] = 0;
					}
					sections[cursection].PointerToLinenumbers = 0;
					sections[cursection].NumberOfLinenumbers = 0;
					sections[cursection].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_LNK_COMDAT | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
					sectiondata[cursection] = CodeSymbols[i].Data;
					cursection++;
					CodeSymbols[i].SectionNumber = cursection;
					CodeSymbols[i].SectionSymbolNumber = cursymnum;
					memcpy(symbols[cursymbol].symbol.N.ShortName, ".text", 8);
					symbols[cursymbol].symbol.Value = 0;
					symbols[cursymbol].symbol.SectionNumber = (SHORT)cursection;
					symbols[cursymbol].symbol.Type = 0;
					symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
					symbols[cursymbol].symbol.NumberOfAuxSymbols = 1;
					symbols[cursymbol].aux.Section.Length = CodeSymbols[i].Size;
					if (CodeSymbols[i].Relocations.size())
					{
						symbols[cursymbol].aux.Section.NumberOfRelocations = (WORD)CodeSymbols[i].Relocations.size();
					}
					else
					{
						symbols[cursymbol].aux.Section.NumberOfRelocations = 0;
					}
					symbols[cursymbol].aux.Section.NumberOfLinenumbers = 0;
					symbols[cursymbol].aux.Section.CheckSum = CRC_MS(CodeSymbols[i].Data, CodeSymbols[i].Size, 0);
					symbols[cursymbol].aux.Section.Number = 0;
					symbols[cursymbol].aux.Section.Selection = 0;
					symbols[cursymbol].aux.Section.bReserved = 0;
					symbols[cursymbol].aux.Section.HighNumber = 0;
					cursymbol++;
					cursymnum++;
					cursymnum++;
				}
				else
				{
					CodeSymbols[i].SectionNumber = cursection;
					CodeSymbols[i].SectionSymbolNumber = cursymnum;
				}
			}
		}
		for (size_t i = 0; i < CodeSymbols.size(); i++)
		{
			CodeSymbols[i].EntrySymbolNumber = cursymnum;
			symbols[cursymbol].symbol.N.Name.Short = 0;
			symbols[cursymbol].symbol.N.Name.Long = stroffset;
			symbols[cursymbol].symbol.Value = (DWORD)CodeSymbols[i].Offset;
			symbols[cursymbol].symbol.SectionNumber = (SHORT)CodeSymbols[i].SectionNumber;
			if (!CodeSymbols[i].IsLocal)
			{
				symbols[cursymbol].symbol.Type = 0x20; //DTYPE_FUNCTION
				symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
			}
			else
			{
				symbols[cursymbol].symbol.Type = 0;
				symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
			}
			symbols[cursymbol].symbol.NumberOfAuxSymbols = 0;
			cursymbol++;
			cursymnum++;
			qstrncpy(strpos, CodeSymbols[i].Name.c_str(), stringtablesize);
			strpos += CodeSymbols[i].Name.length();
			strpos++;
			stroffset += CodeSymbols[i].Name.length();
			stroffset++;
		}
		for (size_t i = 0; i < RDataSymbols.size(); i++)
		{
			if (!RDataSymbols[i].IsExtern)
			{
				memcpy(sections[cursection].Name, ".rdata\0\0", IMAGE_SIZEOF_SHORT_NAME);
				sections[cursection].Misc.VirtualSize = 0;
				sections[cursection].VirtualAddress = 0;
				sections[cursection].SizeOfRawData = RDataSymbols[i].Size;
				sections[cursection].PointerToRawData = CurrentFilePos;
				CurrentFilePos += RDataSymbols[i].Size;
				if (RDataSymbols[i].Relocations.size())
				{
					sections[cursection].PointerToRelocations = CurrentFilePos;
					sections[cursection].NumberOfRelocations = (WORD)RDataSymbols[i].Relocations.size();
					CurrentFilePos += RDataSymbols[i].Relocations.size() * sizeof(IMAGE_RELOCATION);
					sectionrelocations[cursection] = new IMAGE_RELOCATION[RDataSymbols[i].Relocations.size()];
					sectionrelocsymbols[cursection] = &RDataSymbols[i].Relocations;
					for (size_t j = 0; j < RDataSymbols[i].Relocations.size(); j++)
					{
						sectionrelocations[cursection][j].VirtualAddress = RDataSymbols[i].Relocations[j].Rva;
						sectionrelocations[cursection][j].SymbolTableIndex = 0;
						sectionrelocations[cursection][j].Type = RDataSymbols[i].Relocations[j].Type;
					}
				}
				else
				{
					sections[cursection].PointerToRelocations = 0;
					sections[cursection].NumberOfRelocations = 0;
					sectionrelocations[cursection] = 0;
					sectionrelocsymbols[cursection] = 0;
				}
				sections[cursection].PointerToLinenumbers = 0;
				sections[cursection].NumberOfLinenumbers = 0;
				sections[cursection].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_LNK_COMDAT | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_READ;
				sectiondata[cursection] = RDataSymbols[i].Data;
				cursection++;
				RDataSymbols[i].SectionNumber = cursection;
				RDataSymbols[i].SectionSymbolNumber = cursymnum;
				memcpy(symbols[cursymbol].symbol.N.ShortName, ".rdata\0\0", IMAGE_SIZEOF_SHORT_NAME);
				symbols[cursymbol].symbol.Value = 0;
				symbols[cursymbol].symbol.SectionNumber = (SHORT)cursection;
				symbols[cursymbol].symbol.Type = 0;
				symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
				symbols[cursymbol].symbol.NumberOfAuxSymbols = 1;
				symbols[cursymbol].aux.Section.Length = RDataSymbols[i].Size;
				symbols[cursymbol].aux.Section.NumberOfRelocations = 0;
				symbols[cursymbol].aux.Section.NumberOfLinenumbers = 0;
				symbols[cursymbol].aux.Section.CheckSum = CRC_MS(RDataSymbols[i].Data, RDataSymbols[i].Size, 0);
				symbols[cursymbol].aux.Section.Number = 0;
				symbols[cursymbol].aux.Section.Selection = 0;
				symbols[cursymbol].aux.Section.bReserved = 0;
				symbols[cursymbol].aux.Section.HighNumber = 0;
				cursymbol++;
				cursymnum++;
				cursymnum++;
			}
		}
		for (size_t i = 0; i < RDataSymbols.size(); i++)
		{
			RDataSymbols[i].EntrySymbolNumber = cursymnum;
			symbols[cursymbol].symbol.N.Name.Short = 0;
			symbols[cursymbol].symbol.N.Name.Long = stroffset;
			symbols[cursymbol].symbol.Value = 0;
			symbols[cursymbol].symbol.SectionNumber = (SHORT)RDataSymbols[i].SectionNumber;
			symbols[cursymbol].symbol.Type = 0;
			symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
			symbols[cursymbol].symbol.NumberOfAuxSymbols = 0;
			cursymbol++;
			cursymnum++;
			qstrncpy(strpos, RDataSymbols[i].Name.c_str(), stringtablesize);
			strpos += RDataSymbols[i].Name.length();
			strpos++;
			stroffset += RDataSymbols[i].Name.length();
			stroffset++;
		}
		for (size_t i = 0; i < IDataSymbols.size(); i++)
		{
			IDataSymbols[i].EntrySymbolNumber = cursymnum;
			symbols[cursymbol].symbol.N.Name.Short = 0;
			symbols[cursymbol].symbol.N.Name.Long = stroffset;
			symbols[cursymbol].symbol.Value = 0;
			symbols[cursymbol].symbol.SectionNumber = (SHORT)IDataSymbols[i].SectionNumber;
			symbols[cursymbol].symbol.Type = 0;
			symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
			symbols[cursymbol].symbol.NumberOfAuxSymbols = 0;
			cursymbol++;
			cursymnum++;
			qstrncpy(strpos, IDataSymbols[i].Name.c_str(), stringtablesize);
			strpos += IDataSymbols[i].Name.length();
			strpos++;
			stroffset += IDataSymbols[i].Name.length();
			stroffset++;
		}
		for (size_t i = 0; i < BSSSymbols.size(); i++)
		{
			if (!BSSSymbols[i].IsExtern)
			{
				memcpy(sections[cursection].Name, ".bss\0\0\0", IMAGE_SIZEOF_SHORT_NAME);
				sections[cursection].Misc.VirtualSize = 0;
				sections[cursection].VirtualAddress = 0;
				sections[cursection].SizeOfRawData = BSSSymbols[i].Size;
				if (BSSSymbols[i].Data)
				{
					sections[cursection].PointerToRawData = CurrentFilePos;
					CurrentFilePos += BSSSymbols[i].Size;
					if (BSSSymbols[i].Relocations.size())
					{
						sections[cursection].PointerToRelocations = CurrentFilePos;
						sections[cursection].NumberOfRelocations = (WORD)BSSSymbols[i].Relocations.size();
						CurrentFilePos += BSSSymbols[i].Relocations.size() * sizeof(IMAGE_RELOCATION);
						sectionrelocations[cursection] = new IMAGE_RELOCATION[BSSSymbols[i].Relocations.size()];
						sectionrelocsymbols[cursection] = &BSSSymbols[i].Relocations;
						for (size_t j = 0; j < BSSSymbols[i].Relocations.size(); j++)
						{
							sectionrelocations[cursection][j].VirtualAddress = BSSSymbols[i].Relocations[j].Rva;
							sectionrelocations[cursection][j].SymbolTableIndex = 0;
							sectionrelocations[cursection][j].Type = BSSSymbols[i].Relocations[j].Type;
						}
					}
					else
					{
						sections[cursection].PointerToRelocations = 0;
						sections[cursection].NumberOfRelocations = 0;
						sectionrelocations[cursection] = 0;
						sectionrelocsymbols[cursection] = 0;
					}
				}
				else
				{
					sections[cursection].PointerToRawData = 0;
					sections[cursection].PointerToRelocations = 0;
					sections[cursection].NumberOfRelocations = 0;
					sectionrelocations[cursection] = 0;
					sectionrelocsymbols[cursection] = 0;
				}
				sections[cursection].PointerToLinenumbers = 0;
				sections[cursection].NumberOfLinenumbers = 0;
				sections[cursection].Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
				if (BSSSymbols[i].Data)
				{
					sectiondata[cursection] = BSSSymbols[i].Data;
				}
				else
				{
					sectiondata[cursection] = 0;
				}
				cursection++;
				BSSSymbols[i].SectionNumber = cursection;
				BSSSymbols[i].SectionSymbolNumber = cursymnum;
				memcpy(symbols[cursymbol].symbol.N.ShortName, ".bss\0\0\0", IMAGE_SIZEOF_SHORT_NAME);
				symbols[cursymbol].symbol.Value = 0;
				symbols[cursymbol].symbol.SectionNumber = (SHORT)cursection;
				symbols[cursymbol].symbol.Type = 0;
				symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
				symbols[cursymbol].symbol.NumberOfAuxSymbols = 1;
				symbols[cursymbol].aux.Section.Length = BSSSymbols[i].Size;
				symbols[cursymbol].aux.Section.NumberOfRelocations = 0;
				symbols[cursymbol].aux.Section.NumberOfLinenumbers = 0;
				if (BSSSymbols[i].Data)
				{
					symbols[cursymbol].aux.Section.CheckSum = CRC_MS(BSSSymbols[i].Data, BSSSymbols[i].Size, 0);
				}
				else
				{
					symbols[cursymbol].aux.Section.CheckSum = 0;
				}
				symbols[cursymbol].aux.Section.Number = 0;
				symbols[cursymbol].aux.Section.Selection = 0;
				symbols[cursymbol].aux.Section.bReserved = 0;
				symbols[cursymbol].aux.Section.HighNumber = 0;
				cursymbol++;
				cursymnum++;
				cursymnum++;
			}
		}
		for (size_t i = 0; i < BSSSymbols.size(); i++)
		{
			BSSSymbols[i].EntrySymbolNumber = cursymnum;
			symbols[cursymbol].symbol.N.Name.Short = 0;
			symbols[cursymbol].symbol.N.Name.Long = stroffset;
			symbols[cursymbol].symbol.Value = 0;
			symbols[cursymbol].symbol.SectionNumber = (SHORT)BSSSymbols[i].SectionNumber;
			symbols[cursymbol].symbol.Type = 0;
			symbols[cursymbol].symbol.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
			symbols[cursymbol].symbol.NumberOfAuxSymbols = 0;
			cursymbol++;
			cursymnum++;
			qstrncpy(strpos, BSSSymbols[i].Name.c_str(), stringtablesize);
			strpos += BSSSymbols[i].Name.length();
			strpos++;
			stroffset += BSSSymbols[i].Name.length();
			stroffset++;
		}
		FileHeader.PointerToSymbolTable = CurrentFilePos;
		for (int i = 0; i < sectioncount; i++)
		{
			if (sectionrelocations[i])
			{
				qvector<RelocationEntry>* relocs = sectionrelocsymbols[i];
				for (size_t j = 0; j < relocs->size(); j++)
				{
					sectionrelocations[i][j].SymbolTableIndex = (*relocs)[j].Symbol->EntrySymbolNumber;
				}
			}
		}
		FILE* of = qfopen(OutputFull, "wb");
		qfwrite(of, &FileHeader, sizeof(FileHeader));
		for (int i = 0; i < sectioncount; i++)
		{
			qfwrite(of, &sections[i], sizeof(sections[i]));
		}
		for (int i = 0; i < sectioncount; i++)
		{
			if (sectiondata[i])
			{
				qfwrite(of, sectiondata[i], sections[i].SizeOfRawData);
				if (sectionrelocations[i])
				{
					qvector<RelocationEntry>* relocs = sectionrelocsymbols[i];
					qfwrite(of, sectionrelocations[i], sizeof(IMAGE_RELOCATION) * relocs->size());
				}
			}
		}
		for (int i = 0; i < symbolcount; i++)
		{
			qfwrite(of, &symbols[i].symbol, sizeof(symbols[i].symbol));
			if (symbols[i].symbol.NumberOfAuxSymbols)
			{
				qfwrite(of, &symbols[i].aux.Section, sizeof(symbols[i].aux.Section));
			}
		}
		int sz = stringtablesize + 4;
		qfwrite(of, &sz, 4);
		qfwrite(of, strings, stringtablesize);
		qfclose(of);
	}
}

struct ahandler_unlink_export_t : public action_handler_t
{
	virtual int idaapi activate(action_activation_ctx_t*) override
	{
		for (size_t i = 0; i < modules.size(); i++)
		{
			qvector<unlink_entry> module_entries;
			for (size_t j = 0; j < entries.size(); j++)
			{
				if (entries[j].module_index == i)
				{
					module_entries.push_back(entries[j]);
				}
			}
			export_unlinked_module(modules[i], module_entries);
		}
		return true;
	}

	virtual action_state_t idaapi update(action_update_ctx_t*) override
	{
		return AST_ENABLE_ALWAYS;
	}
};
static ahandler_unlink_export_t ahandler_unlink_export;

struct idb_listener_t : public event_listener_t
{
	virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list va)
{
	switch (code)
	{
	case idb_event::renamed:
		refresh_chooser("Unlinker");
		break;
	}

	return 0;
}

idb_listener_t listener;

struct idp_listener_t : public event_listener_t
{
	virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

ssize_t idaapi idp_listener_t::on_event(ssize_t code, va_list va)
{
	switch (code)
	{
	case processor_t::ev_ending_undo:
		refresh_chooser("Unlinker");
		break;
	}

	return 0;
}

idp_listener_t listener2;
struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
	plugin_ctx_t()
	{
		const action_desc_t actions[] =
		{
		  ACTION_DESC_LITERAL_PLUGMOD(UNLINK_NAME, "Unlink", &ahandler_unlink, this, NULL, NULL, -1),
		  ACTION_DESC_LITERAL_PLUGMOD(UNLINK_FUNC_NAME, "Unlink", &ahandler_unlink_func, this, NULL, NULL, -1),
		  ACTION_DESC_LITERAL_PLUGMOD(UNLINK_EXTERN_NAME, "Unlink Extern", &ahandler_unlink_extern, this, NULL, NULL, -1),
		  ACTION_DESC_LITERAL_PLUGMOD(UNLINK_EXPORT_NAME, "Export Unlinked Modules", &ahandler_unlink_export, this, NULL, NULL, -1)
		};

		for (size_t i = 0, n = qnumber(actions); i < n; ++i)
			register_action(actions[i]);


		hook_event_listener(HT_UI, this);
		hook_event_listener(HT_IDB, &listener);
		hook_event_listener(HT_IDP, &listener2);
		char c[50];
		ssize_t i = get_loader_name(c, sizeof(c));
		if (i != -1 && !stricmp(c, "pe"))
		{
			attach_action_to_menu("File/Produce File/Create C Header File...", UNLINK_EXPORT_NAME, SETMENU_APP);
		}
	}
	~plugin_ctx_t()
	{
		unhook_event_listener(HT_UI, this);
		unhook_event_listener(HT_IDB, &listener);
		unhook_event_listener(HT_IDP, &listener2);
		detach_action_from_menu("File/Produce File/Create C Header File...", UNLINK_EXPORT_NAME);
	}
	virtual bool idaapi run(size_t) override;
	virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
	if (code == ui_populating_widget_popup)
	{
		char c[50];
		ssize_t i = get_loader_name(c, sizeof(c));
		if (i != -1 && !stricmp(c, "pe"))
		{
			TWidget* view = va_arg(va, TWidget*);
			if (get_widget_type(view) == BWN_DISASM)
			{
				TPopupMenu* p = va_arg(va, TPopupMenu*);
				attach_action_to_popup(view, p, UNLINK_NAME);
				attach_action_to_popup(view, p, UNLINK_EXTERN_NAME);
			}

			if (get_widget_type(view) == BWN_FUNCS)
			{
				TPopupMenu* p = va_arg(va, TPopupMenu*);
				attach_action_to_popup(view, p, UNLINK_FUNC_NAME);
			}
		}
	}
	else if (code == ui_database_inited)
	{
		if (netnode::inited())
		{
			netnode node("$ unlinker module node");
			if (exist(node))
			{
				modules.clear();
				size_t modulecount;
				node.supval(0, &modulecount, sizeof(modulecount));
				for (size_t i = 0; i < modulecount; i++)
				{
					qstring str;
					node.supstr(&str, i + 1);
					modules.push_back(str);
				}
			}
			netnode node2("$ unlinker entry node");
			if (exist(node2))
			{
				entries.clear();
				size_t entrycount;
				node2.supval(0, &entrycount, sizeof(entrycount));
				int val = 1;
				for (size_t i = 0; i < entrycount; i++)
				{
					unlink_entry e;
					node2.supval(val, &e.ea, sizeof(e.ea));
					val++;
					node2.supval(val, &e.is_extern, sizeof(e.is_extern));
					val++;
					node2.supval(val, &e.is_local, sizeof(e.is_local));
					val++;
					node2.supval(val, &e.module_index, sizeof(e.module_index));
					val++;
					entries.push_back(e);
				}
			}
		}
	}
	else if (code == ui_saving)
	{
		netnode node;
		node.create("$ unlinker module node");
		if (node != BADNODE)
		{
			node.supdel_all(stag);
			size_t size = modules.size();
			node.supset(0, &size, sizeof(size));
			for (size_t i = 0; i < size; i++)
			{
				node.supset(i + 1, modules[i].c_str());
			}
		}
		netnode node2;
		node2.create("$ unlinker entry node");
		if (node2 != BADNODE)
		{
			node2.supdel_all(stag);
			size_t size = entries.size();
			node2.supset(0, &size, sizeof(size));
			int val = 1;
			for (size_t i = 0; i < size; i++)
			{
				node2.supset(val, &entries[i].ea, sizeof(entries[i].ea));
				val++;
				node2.supset(val, &entries[i].is_extern, sizeof(entries[i].is_extern));
				val++;
				node2.supset(val, &entries[i].is_local, sizeof(entries[i].is_local));
				val++;
				node2.supset(val, &entries[i].module_index, sizeof(entries[i].module_index));
				val++;
			}
		}
	}
	return 0;
}

entry_chooser_t chooser;
bool idaapi plugin_ctx_t::run(size_t)
{
	char c[50];
	ssize_t i = get_loader_name(c, sizeof(c));
	if (i != -1 && !stricmp(c, "pe"))
	{
		chooser.choose();
	}
	return true;
}

static plugmod_t* idaapi init()
{
	return new plugin_ctx_t;
}

static const char wanted_name[] = "Unlinker";

static const char comment[] = "Unlinker";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // plugin flags
  init,                 // initialize
  nullptr,
  nullptr,
  comment,              // long comment about the plugin
						// it could appear in the status line
						// or as a hint

  "",                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  ""         // the preferred hotkey to run the plugin
};
