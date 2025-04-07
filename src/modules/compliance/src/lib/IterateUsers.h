// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ITERATE_USERS_H
#define COMPLIANCE_ITERATE_USERS_H

#include <CommonUtils.h>
#include <ContextInterface.h>
#include <MmiResults.h>
#include <Result.h>
#include <cerrno>
#include <memory>
#include <pwd.h>

namespace compliance
{
enum class BreakOnNonCompliant
{
    True,
    False
};

template <typename Callable>
Result<Status> IterateUsers(Callable callable, BreakOnNonCompliant breakOnNonCompliant, ContextInterface& context)
{
    auto result = Status::Compliant;
    struct passwd* pwd = nullptr;
    setpwent();
    for (errno = 0, pwd = getpwent(); nullptr != pwd; errno = 0, pwd = getpwent())
    {
        auto callbackResult = callable(pwd);
        if (!callbackResult.HasValue())
        {
            OsConfigLogDebug(context.GetLogHandle(), "Iteration failed");
            endpwent();
            return callbackResult.Error();
        }

        if (callbackResult.Value() != Status::Compliant)
        {
            result = Status::NonCompliant;
            if (breakOnNonCompliant == BreakOnNonCompliant::True)
            {
                OsConfigLogDebug(context.GetLogHandle(), "Iteration stopped");
                break;
            }
            else
            {
                OsConfigLogDebug(context.GetLogHandle(), "Callback returned false, but continuing");
            }
        }
    }

    int status = errno;
    endpwent();
    if (0 != status)
    {
        return Error(std::string("getpwent failed: ") + strerror(status), status);
    }

    return result;
}
} // namespace compliance

#endif // COMPLIANCE_ITERATE_USERS_H
