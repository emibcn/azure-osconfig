// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ITERATE_DIRECTORIES_H
#define COMPLIANCE_ITERATE_DIRECTORIES_H

#include <CommonUtils.h>
#include <ContextInterface.h>
#include <Indicators.h>
#include <MmiResults.h>
#include <Result.h>
#include <cerrno>
#include <dirent.h>
#include <memory>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace compliance
{
namespace
{
constexpr size_t maxDepth = 32;
template <typename Callable>
Result<Status> FileTreeWalk(const std::string& path, Callable callable, BreakOnNonCompliant breakOnNonCompliant, ContextInterface& context, size_t depth)
{
    if (depth > maxDepth)
    {
        return Error("Maximum recursion depth reached");
    }

    auto* dir = opendir(path.c_str());
    if (nullptr == dir)
    {
        int status = errno;
        if (ENOENT == status)
        {
            return Status::Compliant;
        }

        OsConfigLogError(context.GetLogHandle(), "Failed to open directory '%s': %s", path.c_str(), strerror(status));
        return Error("Failed to open directory '" + path + "': " + strerror(status), status);
    }

    Result<Status> result = Status::Compliant;
    Result<Status> subResult = Status::Compliant;
    struct dirent* entry = nullptr;
    for (errno = 0, entry = readdir(dir); nullptr != entry; errno = 0, entry = readdir(dir))
    {
        if (entry->d_type == DT_DIR)
        {
            if (!strcmp(entry->d_name, ".") != 0 || !strcmp(entry->d_name, "..") != 0)
            {
                continue;
            }

            // Recursively call FTW for subdirectories
            subResult = FileTreeWalk(path + "/" + entry->d_name, callable, breakOnNonCompliant, context, depth + 1);
            if (!subResult.HasValue())
            {
                OsConfigLogDebug(context.GetLogHandle(), "Callback returned an error: %s", subResult.Error().message.c_str());
                return subResult.Error();
            }

            if (subResult.Value() != Status::Compliant)
            {
                result = Status::NonCompliant;
                if (breakOnNonCompliant == BreakOnNonCompliant::True)
                {
                    OsConfigLogDebug(context.GetLogHandle(), "Callback returned NonCompliant status, stopping iteration");
                    break;
                }
            }
        }

        struct stat sb;
        std::string directory = path + "/" + entry->d_name;
        OsConfigLogDebug(context.GetLogHandle(), "Checking file: '%s'", directory.c_str());
        if (0 != stat(directory.c_str(), &sb))
        {
            int status = errno;
            OsConfigLogError(context.GetLogHandle(), "Failed to stat '%s': %s", directory.c_str(), strerror(status));
            result = Error("Failed to stat '" + directory + "': " + strerror(status), status);
            break;
        }

        subResult = callable(path, entry->d_name, sb);
        if (!subResult.HasValue())
        {
            OsConfigLogDebug(context.GetLogHandle(), "Callback returned an error: %s", subResult.Error().message.c_str());
            return subResult.Error();
        }

        if (subResult.Value() != Status::Compliant)
        {
            result = Status::NonCompliant;
            if (breakOnNonCompliant == BreakOnNonCompliant::True)
            {
                OsConfigLogDebug(context.GetLogHandle(), "Callback returned NonCompliant status, stopping iteration");
                break;
            }
        }
    }

    int status = errno;
    closedir(dir);
    if (!result.HasValue())
    {
        OsConfigLogDebug(context.GetLogHandle(), "Iteration failed with an error: %s", result.Error().message.c_str());
        return result.Error();
    }

    if (0 != status)
    {
        OsConfigLogError(context.GetLogHandle(), "Failed to iterate directory '%s': %s", path.c_str(), strerror(status));
        return Error("Failed to iterate directory '" + path + "': " + strerror(status), status);
    }

    return result;
}

} // anonymous namespace

template <typename Callable>
Result<Status> FileTreeWalk(const std::string& path, Callable callable, BreakOnNonCompliant breakOnNonCompliant, ContextInterface& context)
{
    return FileTreeWalk(path, callable, breakOnNonCompliant, context, 0);
}
} // namespace compliance

#endif // COMPLIANCE_ITERATE_DIRECTORIES_H
