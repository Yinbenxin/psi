#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "psi/volepsi/vole_psi.h"

namespace py = pybind11;
namespace psi {

PYBIND11_MODULE(libvolepsi, m) {
  py::class_<VolePsi>(m, "VolePsi")
      .def(py::init<size_t>())
      .def("Run", &VolePsi::Run,
           py::arg("role"),
           py::arg("items_num"),
           py::arg("fast_mode"),
           py::arg("malicious"));
}

}  // namespace psi
