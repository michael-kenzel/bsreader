#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <new>
#include <bit>
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

		const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, nullptr);

		if (file == INVALID_HANDLE_VALUE)
			throw_last_error();


		auto volume_path = get_volume_name(get_volume_path(path));

		const HANDLE volume = CreateFileW(volume_path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

		if (volume == INVALID_HANDLE_VALUE)
			throw_last_error();

		STORAGE_DEVICE_NUMBER storage_device;
		STORAGE_PROPERTY_QUERY storage_query_property = {
			.PropertyId = StorageAccessAlignmentProperty
		};
		STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR storage_alignment_desc;
		if (DWORD num_bytes_returned; !DeviceIoControl(volume, IOCTL_STORAGE_QUERY_PROPERTY, &storage_query_property, sizeof(storage_query_property), &storage_alignment_desc, sizeof(storage_alignment_desc), &num_bytes_returned, nullptr))
			throw_last_error();


		LARGE_INTEGER file_size;
		if (!GetFileSizeEx(file, &file_size))
			throw_last_error();

		constexpr long long buffer_size = 1024*1024*512;
		constexpr int num_buffers = 4;
		auto buffer = static_cast<std::byte*>(::operator new(buffer_size * num_buffers, std::align_val_t(4096)));

#if 1
		// IORING_CAPABILITIES caps;
		// QueryIoRingCapabilities(&caps);

		HIORING ioring;
		throw_error(CreateIoRing(IORING_VERSION_3, {}, 1024, 1024, &ioring));

		throw_error(BuildIoRingRegisterFileHandles(ioring, 1, &file, 1));

		IORING_BUFFER_INFO buffer_info = { buffer, buffer_size*num_buffers };
		throw_error(BuildIoRingRegisterBuffers(ioring, 1, &buffer_info, 2));

		throw_error(SubmitIoRing(ioring, 2, INFINITE, nullptr));

		IORING_CQE cqe;
		throw_error(PopIoRingCompletion(ioring, &cqe));
		throw_error(cqe.ResultCode);
		throw_error(PopIoRingCompletion(ioring, &cqe));
		throw_error(cqe.ResultCode);

		long long read_offset = 0;
		long long bytes_read = 0;

		for (int i = 0; i < num_buffers; ++i)
		{
			throw_error(BuildIoRingReadFile(ioring, IoRingHandleRefFromIndex(0), IoRingBufferRefFromIndexAndOffset(0, i * buffer_size), buffer_size, read_offset, i, IOSQE_FLAGS_NONE));
			read_offset += buffer_size;
		}

		while (true)
		{
			throw_error(SubmitIoRing(ioring, 1, INFINITE, nullptr));

			throw_error(PopIoRingCompletion(ioring, &cqe));

			if (cqe.ResultCode != S_OK)
				break;

			long long read_size = std::min<long long>(file_size.QuadPart - read_offset, buffer_size);

			int i = cqe.UserData;
			throw_error(BuildIoRingReadFile(ioring, IoRingHandleRefFromIndex(0), IoRingBufferRefFromIndexAndOffset(0, i * buffer_size), read_size, read_offset, i, IOSQE_FLAGS_NONE));
			read_offset += read_size;
		}

		bytes_read = read_offset;
#else
		HANDLE iocp = CreateIoCompletionPort(file, 0, 0, 0);

		if (!iocp)
			throw_last_error();


		long long read_offset = 0;
		long long bytes_read = 0;

		OVERLAPPED o[num_buffers] = {};

		for (int i = 0; i < num_buffers; ++i)
		{
			o[i] = {
				.Offset = static_cast<DWORD>(read_offset & 0xFFFFFFFF),
				.OffsetHigh = static_cast<DWORD>(read_offset >> 32),
			};

			ReadFile(file, buffer + i * buffer_size, buffer_size, nullptr, o + i);
			if (DWORD err = GetLastError(); err != ERROR_IO_PENDING)
				throw_last_error(err);
			read_offset += buffer_size;
		}

		auto read = [&, read_offset = std::atomic_ref<long long>(read_offset), bytes_read = std::atomic_ref<long long>(bytes_read)]
		{
			while (true)
			{
				OVERLAPPED* po;
				DWORD bytes_transferred;
				ULONG_PTR key;
				if (!GetQueuedCompletionStatus(iocp, &bytes_transferred, &key, &po, INFINITE))
					break;

				bytes_read.fetch_add(bytes_transferred, std::memory_order::relaxed);

				auto i = ((po - o) + 1) % num_buffers;

				auto offset = read_offset.fetch_add(buffer_size, std::memory_order::relaxed);

				if (offset >= file_size.QuadPart)
					break;

				o[i] = {
					.Offset = static_cast<DWORD>(offset & 0xFFFFFFFF),
					.OffsetHigh = static_cast<DWORD>(offset >> 32),
				};

				ReadFile(file, buffer + i * buffer_size, buffer_size, nullptr, o + i);
				if (DWORD err = GetLastError(); err != ERROR_IO_PENDING)
					throw_last_error(err);
			}
		};

		std::thread threads[] = {
			std::thread(read), std::thread(read), std::thread(read)
		};

		read();

		for (auto&& t : threads)
			t.join();
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
