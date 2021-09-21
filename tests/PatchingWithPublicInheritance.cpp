/*
 * SPDX-FileCopyrightText: 2021 George Tokmaji
 * SPDX-License-Identifier: MIT
*/

#include <ctime>

#include "vtablepatch.hpp"

time_t GetTimePatch(class TestClass *const _this);

class TestClass : public VTablePatch::PatchedClassBase<TestClass>
{
public:
	TestClass()
	{
		PatchVTable(VTablePatch::FunctionPointerMapping{&TestClass::GetTime, &TestClass::GetPatchedTime});
	}

public:
	virtual time_t GetTime() { return std::launder(this)->GetTime(); }

	static time_t GetPatchedTime(TestClass *const _this)
	{
		return _this->patchedTime;
	}

private:
	time_t patchedTime{time(nullptr)};
};

int main()
{
	TestClass testClass;
	return testClass.GetTime() == TestClass::GetPatchedTime(&testClass) ? EXIT_SUCCESS : EXIT_FAILURE;
	return 0;
}
