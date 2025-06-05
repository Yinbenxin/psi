#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "psi/volepsi/vole_psi.h"

namespace py = pybind11;
namespace psi {

PYBIND11_MODULE(libvolepsi, m) {
  py::class_<VolePsi>(m, "VolePsi")
      .def(py::init<size_t, std::string, std::string, std::string, size_t, size_t, std::string, size_t, bool, bool, bool, bool, std::string, const std::map<std::string, std::string>&>(),
           py::arg("role"),
           py::arg("taskid"),
           py::arg("party"),
           py::arg("redis"),
           py::arg("sysectbits") = 112,
           py::arg("psi_type") = 1,
           py::arg("log_dir") = ".",
           py::arg("log_level") = 2,
           py::arg("log_with_console") = true,
           py::arg("net_log_switch") = false,
           py::arg("server_output") = true,
           py::arg("use_redis") = true,
           py::arg("chl_type") = "mem",
           py::arg("meta") = std::map<std::string, std::string>())
      .def("Run", &VolePsi::Run,
           py::arg("role"),
           py::arg("input"),
           py::arg("fast_mode") = true,
           py::arg("malicious") = false,
           py::arg("broadcast_result") = true);
}

}  // namespace psi
