#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <new>
#include <bit>
#include <numeric>
#include <iterator>
#include <string_view>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <filesystem>
#include <iostream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NTDDI_VERSION NTDDI_WIN10_NI
#include <Windows.h>
#include <winioctl.h>
#include <ioringapi.h>


constexpr unsigned long long read_uint64(const std::byte* bytes)
{
	return (static_cast<unsigned long long>(bytes[0]) <<  0) |
	       (static_cast<unsigned long long>(bytes[1]) <<  8) |
	       (static_cast<unsigned long long>(bytes[2]) << 16) |
	       (static_cast<unsigned long long>(bytes[3]) << 24) |
	       (static_cast<unsigned long long>(bytes[4]) << 32) |
	       (static_cast<unsigned long long>(bytes[5]) << 40) |
	       (static_cast<unsigned long long>(bytes[6]) << 48) |
	       (static_cast<unsigned long long>(bytes[7]) << 56);
}

constexpr unsigned long long read_uint40(const std::byte* bytes)
{
	return (static_cast<unsigned long long>(bytes[0]) <<  0) |
	       (static_cast<unsigned long long>(bytes[1]) <<  8) |
	       (static_cast<unsigned long long>(bytes[2]) << 16) |
	       (static_cast<unsigned long long>(bytes[3]) << 24) |
	       (static_cast<unsigned long long>(bytes[4]) << 32);
}

constexpr unsigned long read_uint24(const std::byte* bytes)
{
	return (static_cast<unsigned long>(bytes[0]) <<  0) |
	       (static_cast<unsigned long>(bytes[1]) <<  8) |
	       (static_cast<unsigned long>(bytes[2]) << 16);
}

constexpr unsigned int read_uint16(const std::byte* bytes)
{
	return (static_cast<unsigned int>(bytes[0]) <<  0) |
	       (static_cast<unsigned int>(bytes[1]) <<  8);
}

constexpr unsigned long long read_td40(const std::byte* bytes)
{
	return std::bit_cast<double>(static_cast<std::uint64_t>(read_uint40(bytes) << 24));
}

constexpr unsigned long long read_tf24(const std::byte* bytes)
{
	return std::bit_cast<float>(static_cast<std::uint32_t>(read_uint24(bytes) << 24));
}


namespace
{
	struct win32error : std::exception
	{
		HRESULT error_code;

		win32error(HRESULT error_code) : error_code(error_code) {}

		const char* what() const noexcept override { return "Win32 error"; }
	};

	inline HRESULT throw_error(HRESULT res)
	{
		if (!SUCCEEDED(res))
			throw win32error(res);
		return res;
	}

	inline auto throw_last_error(DWORD err = GetLastError())
	{
		throw_error(HRESULT_FROM_WIN32(err));
	}

	auto get_volume_path(const std::filesystem::path& path)
	{
		std::wstring buffer = std::filesystem::absolute(path);
		if (!GetVolumePathNameW(path.c_str(), buffer.data(), buffer.length()))
			throw_last_error();
		return std::filesystem::path(std::move(buffer));
	}

	auto get_volume_name(const std::filesystem::path& volume_path)
	{
		std::wstring buffer;
		buffer.resize_and_overwrite(50, [&](WCHAR* buffer, std::size_t size)
		{
			if (!GetVolumeNameForVolumeMountPointW(volume_path.c_str(), buffer, size))
				throw_last_error();
			return std::wstring_view(buffer).length() - 1;
		});
		return std::filesystem::path(std::move(buffer));
	}

	template <int num_buffers = 4>
	auto consume(const std::filesystem::path& path, auto&& sink)
	{
		std::clog << "reading " << path.string() << '\n' << std::flush;

		const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, nullptr);

		if (file == INVALID_HANDLE_VALUE)
			throw_last_error();


		auto volume_path = get_volume_name(get_volume_path(path));

		std::clog << "   on " << volume_path.string() << '\n' << std::flush;

		const HANDLE volume = CreateFileW(volume_path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

		if (volume == INVALID_HANDLE_VALUE)
			throw_last_error();

		STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR storage_alignment_desc;
		{
			STORAGE_PROPERTY_QUERY storage_query_property = {
				.PropertyId = StorageAccessAlignmentProperty
			};
			if (DWORD num_bytes_returned; !DeviceIoControl(volume, IOCTL_STORAGE_QUERY_PROPERTY, &storage_query_property, sizeof(storage_query_property), &storage_alignment_desc, sizeof(storage_alignment_desc), &num_bytes_returned, nullptr))
				throw_last_error();
		}

		std::clog << "   physical sector size " << storage_alignment_desc.BytesPerPhysicalSector << " B\n" << std::flush;

		LARGE_INTEGER file_size;
		if (!GetFileSizeEx(file, &file_size))
			throw_last_error();

		const long long min_read_size = std::lcm(std::lcm(33, 256), storage_alignment_desc.BytesPerPhysicalSector);
		const long long read_size = min_read_size * (2 * 1024 * 1024 / min_read_size);
		const long long buffer_alignment = std::lcm(storage_alignment_desc.BytesPerPhysicalSector, std::bit_ceil(storage_alignment_desc.BytesPerPhysicalSector));
		const long long buffer_size = (read_size + buffer_alignment - 1) / buffer_alignment * buffer_alignment;
		auto buffer = static_cast<std::byte*>(::operator new(buffer_size * num_buffers, std::align_val_t(buffer_alignment)));

		std::clog << "   using " << num_buffers << " buffers sized " << buffer_size << " B alignment " << buffer_alignment << " read size " << read_size << " B to read " << file_size.QuadPart << " B\n" << std::flush;

#if 1
		// IORING_CAPABILITIES caps;
		// QueryIoRingCapabilities(&caps);

		HIORING ioring;
		throw_error(CreateIoRing(IORING_VERSION_3, {}, 1024, 1024, &ioring));

		throw_error(BuildIoRingRegisterFileHandles(ioring, 1, &file, 1));

		IORING_BUFFER_INFO buffer_info = { buffer, static_cast<UINT32>(buffer_size*num_buffers) };
		throw_error(BuildIoRingRegisterBuffers(ioring, 1, &buffer_info, 2));

		throw_error(SubmitIoRing(ioring, 2, INFINITE, nullptr));
		{
			IORING_CQE cqe;
			throw_error(PopIoRingCompletion(ioring, &cqe));
			throw_error(cqe.ResultCode);
			throw_error(PopIoRingCompletion(ioring, &cqe));
			throw_error(cqe.ResultCode);
		}

		long long read_offset = 0;
		long long bytes_read = 0;
		long long active_read_size[num_buffers];

		for (int i = 0; i < num_buffers && read_offset < file_size.QuadPart; ++i)
		{
			throw_error(BuildIoRingReadFile(ioring, IoRingHandleRefFromIndex(0), IoRingBufferRefFromIndexAndOffset(0, i * buffer_size), read_size, read_offset, i, IOSQE_FLAGS_NONE));
			read_offset += read_size;
		}

		while (bytes_read != file_size.QuadPart)
		{
			throw_error(SubmitIoRing(ioring, 1, INFINITE, nullptr));

			IORING_CQE cqe;
			throw_error(PopIoRingCompletion(ioring, &cqe));

			if (cqe.ResultCode == HRESULT_FROM_WIN32(ERROR_HANDLE_EOF))
				continue;

			if (cqe.ResultCode != S_OK)
				throw_error(cqe.ResultCode);

			int i = static_cast<int>(cqe.UserData);

			bytes_read += cqe.Information;

			if (read_offset < file_size.QuadPart)
			{
				throw_error(BuildIoRingReadFile(ioring, IoRingHandleRefFromIndex(0), IoRingBufferRefFromIndexAndOffset(0, i * buffer_size), read_size, read_offset, i, IOSQE_FLAGS_NONE));
				read_offset += read_size;
			}
		}
#else
		HANDLE iocp = CreateIoCompletionPort(file, 0, 0, 0);

		if (!iocp)
			throw_last_error();


		long long read_offset = 0;
		long long bytes_read = 0;

		OVERLAPPED o[num_buffers] = {};

		for (int i = 0; i < num_buffers && read_offset < file_size.QuadPart; ++i)
		{
			o[i] = {
				.Offset = static_cast<DWORD>(read_offset & 0xFFFFFFFF),
				.OffsetHigh = static_cast<DWORD>(read_offset >> 32),
			};

			ReadFile(file, buffer + i * buffer_size, read_size, nullptr, o + i);
			if (DWORD err = GetLastError(); err != ERROR_IO_PENDING)
				throw_last_error(err);
			read_offset += read_size;
		}

		auto read = [&, read_offset = std::atomic_ref<long long>(read_offset), bytes_read = std::atomic_ref<long long>(bytes_read)]
		{
			while (bytes_read.load(std::memory_order::relaxed) != file_size.QuadPart)
			{
				OVERLAPPED* po;
				DWORD bytes_transferred;
				ULONG_PTR key;
				if (!GetQueuedCompletionStatus(iocp, &bytes_transferred, &key, &po, INFINITE))
				{
					if (DWORD err = GetLastError(); err == ERROR_ABANDONED_WAIT_0)
						break;
					else
						throw_last_error(err);
				}

				if (bytes_read.fetch_add(bytes_transferred, std::memory_order::relaxed) + bytes_transferred == file_size.QuadPart)
					CloseHandle(iocp);

				auto i = ((po - o) + 1) % num_buffers;

				if (auto offset = read_offset.fetch_add(read_size, std::memory_order::relaxed); offset < file_size.QuadPart)
				{
					o[i] = {
						.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF),
						.OffsetHigh = static_cast<DWORD>(offset >> 32),
					};

					ReadFile(file, buffer + i * buffer_size, read_size, nullptr, o + i);
					if (DWORD err = GetLastError(); err != ERROR_IO_PENDING)
						throw_last_error(err);
				}
			}
		};

		std::jthread threads[] = {
			std::jthread(read), std::jthread(read), std::jthread(read)
		};

		read();
#endif
		return bytes_read;
	}
}

int main(int argc, char** argv)
{
	try
	{
		if (argc != 2)
		{
			std::cerr << "usage: bsreader <file name>\n";
			return -1;
		}

		auto path = std::filesystem::path(argv[1]);

		auto start = std::chrono::steady_clock::now();

		auto bytes_read = consume(path, []()
		{
		// std::vector<double> stars;
		// for (auto ptr = bytes + 256; ptr < bytes + file_size.QuadPart; ptr += 33)
		// {
		// 	auto gaia_id = read_uint64(ptr);
		// 	auto x = read_td40(ptr + 8);
		// 	auto y = read_td40(ptr + 13);
		// 	auto z = read_td40(ptr + 18);
		// 	auto li = read_tf24(ptr + 23);
		// 	auto li_u = read_tf24(ptr + 26);
		// 	auto c = read_uint16(ptr + 28);
		// 	auto c_u = read_uint16(ptr + 30);

		// 	stars.push_back(x);
		// }
		});

		auto end = std::chrono::steady_clock::now();

		auto t = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

		std::clog << "read " << bytes_read / (1024.0 * 1024.0 * 1024.0) << " GiB in " << t * 0.001 << " s (" << bytes_read * 1000.0 / (1024.0 * 1024.0 * 1024.0 * t) << " GiB/s)\n";

		// std::clog << n << " stars " << std::chrono::duration_cast<std::chrono::seconds>(end - start).count() << "s\n";
	}
	catch (const win32error& e)
	{
		std::cerr << "ERROR: 0x" << std::hex << e.error_code << '\n';
		return -1;
	}
	catch (const std::exception& e)
	{
		std::cerr << "ERROR: " << e.what() << '\n';
		return -1;
	}
	catch (...)
	{
		std::cerr << "ERROR: unknown exception\n";
		return -128;
	}

	return 0;
}
