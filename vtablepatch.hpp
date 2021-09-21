/*
 * SPDX-FileCopyrightText: 2021 George Tokmaji
 * SPDX-License-Identifier: MIT
*/

#pragma once

#if !defined(VTABLEPATCH_MSVC_LAYOUT) && !defined(VTABLEPATCH_ITANIUM_LAYOUT)
#ifdef _WIN32
#ifdef ____MINGW32__
#define VTABLEPATCH_ITANIUM_LAYOUT
#elif defined(_MSC_VER) || defined(__clang__)
#define VTABLEPATCH_MSVC_LAYOUT
#else
#error Unknown compiler. Plase define VTABLEPATCH_MSVC_LAYOUT or VTABLEPATCH_ITANIUM_LAYOUT depending on the vtable layout.
#endif
#else
#define VTABLEPATCH_ITANIUM_LAYOUT
#endif
#endif

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <tuple>
#include <utility>

#ifdef VTABLEPATCH_MSVC_LAYOUT
#pragma push_macro("NOMINMAX")
#undef NOMINMAX
#define NOMINMAX
#include <Windows.h>
#pragma pop_macro("NOMINMAX")
#endif

namespace VTablePatch
{
	static void *AlignedAlloc(const std::size_t size, const std::size_t alignment)
	{
#ifdef VTABLEPATCH_MSVC_LAYOUT
		return _aligned_alloc(size, alignment);
#else
		return std::aligned_alloc(alignment, size);
#endif
	}

	static void AlignedFree(void* const ptr)
	{
#ifdef VTABLEPATCH_MSVC_LAYOUT
		_aligned_free(ptr);
#else
		free(ptr);
#endif
	}

	struct VTable
	{
		void *rttiCompleteObjectLocator;

		std::uintptr_t vtableEntries[];

		static VTable *FromVTablePointer(void *const pointer)
		{
			return reinterpret_cast<VTable *>(reinterpret_cast<char *>(pointer) - offsetof(VTable, vtableEntries));
		}

		void *ToVTablePointer()
		{
			return reinterpret_cast<char *>(this) + offsetof(VTable, vtableEntries);
		}

		static VTable *New(const std::size_t dataSize)
		{
			return reinterpret_cast<VTable *>(AlignedAlloc(sizeof(void *) + dataSize, alignof(VTable)));
		}

		static void Delete(VTable *const ptr)
		{
			ptr->~VTable();
			AlignedFree(ptr);
		}
	};

	template<typename T>
	struct FunctionPointerMapping
	{
		T Member;
		T Target;
	};

	template<typename Ret, typename Class, typename... Args>
	struct FunctionPointerMapping<Ret(Class::*)(Args...)>
	{
		using MemberPointerType = Ret(Class::*)(Args...);
		using TargetPointerType = Ret(*)(Class *, Args...);
		using ReturnType = Ret;
		using ArgumentTypes = std::tuple<Args...>;

		MemberPointerType Member;
		TargetPointerType Target;

		FunctionPointerMapping(MemberPointerType member, TargetPointerType target) : Member{member}, Target{target} {}
	};

	template<typename T> FunctionPointerMapping(T, T) -> FunctionPointerMapping<T>;
	template<typename Ret, typename Class, typename...Args> FunctionPointerMapping(Ret(Class::*)(Args...), Ret(*)(Class *, Args...)) -> FunctionPointerMapping<Ret(Class::*)(Args...)>;

	template<typename Class>
	class PatchedClassBase
	{
	private:
		template<typename T>
		struct AlignedDeleter
		{
		public:
			void operator()(T *const ptr) noexcept(noexcept(std::declval<T>().~T()))
			{
				T::Delete(ptr);
			}
		};

	public:
		template<typename... Args> void PatchVTable(FunctionPointerMapping<Args>... args);

	private:
		void **GetVTable();
		template<typename T> std::uintptr_t PointerToFunctionMemberToPointer(T pfm);
		void ReplaceVTable(struct VTable *newVTable);
		template<typename Ret, typename...Args> std::uintptr_t GetVTableIndexFromPointer(Ret(Class::*pointer)(Args...));

#ifdef VTABLEPATCH_MSVC_LAYOUT
		int ExceptionFilter(std::uintptr_t &location, int exceptionCode, LPEXCEPTION_POINTERS exceptionInformation);
#endif

	private:
		using VTablePtr = std::unique_ptr<VTable, AlignedDeleter<VTable>>;
		VTablePtr newVTable{nullptr, {}};
	};

	template<typename Class>
	void **PatchedClassBase<Class>::GetVTable()
	{
		return *reinterpret_cast<void ***>(static_cast<Class *>(this)); // NOLINT
	}

	template<typename Class>
	template<typename... Args>
	void PatchedClassBase<Class>::PatchVTable(FunctionPointerMapping<Args>... args)
	{
		static_assert(std::is_polymorphic_v<Class>);
		static_assert(std::conjunction_v<std::is_member_function_pointer<Args>...>);

		void **const oldVTable{GetVTable()};
		void *const objectLocator{oldVTable[-1]};

#ifdef VTABLEPATCH_MSVC_ABI
		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);

		const auto firstVTableEntry = reinterpret_cast<std::uintptr_t>(oldVTable[0]);
		const std::size_t structSize{sizeof(void *) + std::max<DWORD>(((firstVTableEntry / systemInfo.dwPageSize) + 1) * systemInfo.dwPageSize - firstVTableEntry, sizeof(void *) * sizeof...(args))};

		VTablePtr pseudoVTable{VTable::New(structSize), {}};
		pseudoVTable->rttiCompleteObjectLocator = objectLocator;

		for (std::size_t i{0}; i < structSize / sizeof(void *); ++i)
		{
			pseudoVTable->vtableEntries[i] = i;
		}

		ReplaceVTable(pseudoVTable.get());
#endif

		std::map<std::uintptr_t, FunctionPointerMapping<std::uintptr_t>> newVTableMapping;

		(newVTableMapping.insert({GetVTableIndexFromPointer(args.Member), FunctionPointerMapping<std::uintptr_t>{PointerToFunctionMemberToPointer(args.Member), reinterpret_cast<std::uintptr_t>(args.Target)}}), ...);

		const std::uintptr_t maxIndex{newVTableMapping.rbegin()->first};
		const std::size_t newVTableSize{(maxIndex + 1) * sizeof(void *)};

		newVTable.reset(VTable::New(newVTableSize));
		newVTable->rttiCompleteObjectLocator = objectLocator;

		for (std::size_t i{0}; i < maxIndex + 1; ++i)
		{
			if (const auto it = newVTableMapping.find(i); it != newVTableMapping.cend())
			{
				newVTable->vtableEntries[i] = it->second.Target;
			}
			else
			{
				newVTable->vtableEntries[i] = reinterpret_cast<std::uintptr_t>(oldVTable[i]);
			}
		}

		ReplaceVTable(newVTable.get());
	}

	template<typename Class>
	template<typename T>
	std::uintptr_t PatchedClassBase<Class>::PointerToFunctionMemberToPointer(T pfm)
	{
		std::uintptr_t ret;
		std::memcpy(&ret, &pfm, sizeof(ret));
		return ret;
	}

	template<typename Class>
	void PatchedClassBase<Class>::ReplaceVTable(struct VTable *newVTable)
	{
		void *const ptr{newVTable->ToVTablePointer()};
		std::memcpy(std::launder(static_cast<Class *>(this)), &ptr, sizeof(newVTable));
	}

	template<typename Class>
	template<typename Ret, typename...Args>
	std::uintptr_t PatchedClassBase<Class>::GetVTableIndexFromPointer(Ret(Class::*pointer)(Args...))
	{
#ifdef VTABLEPATCH_MSVC_LAYOUT
		auto location = static_cast<std::uintptr_t>(-1);

		__try
		{
			(std::launder(static_cast<Class *>(this))->*pointer)(std::declval<Args>()...);
		}
		__except (ExceptionFilter(location, GetExceptionCode(), GetExceptionInformation()))
		{
		}

		if (location == -1)
		{
			throw std::runtime_error{"Failed"};
		}

		return location;
#else
		return PointerToFunctionMemberToPointer(pointer) - 1;
#endif
	}

#ifdef VTABLEPATCH_MSVC_LAYOUT
	template<typename Class>
	int PatchedClassBase<Class>::ExceptionFilter(std::uintptr_t &location, int exceptionCode, LPEXCEPTION_POINTERS exceptionInformation)
	{
		if (exceptionCode != EXCEPTION_ACCESS_VIOLATION)
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		location = static_cast<std::uintptr_t>(exceptionInformation->ExceptionRecord->ExceptionInformation[1]);

		return EXCEPTION_EXECUTE_HANDLER;
	}
#endif
}
