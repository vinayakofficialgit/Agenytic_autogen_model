// import React from 'react'
import { useNavigate, Link } from "react-router-dom";
import { useSelector, useDispatch } from "react-redux";
import { setalert } from "../Slices/alertSlice";
import ShoppingCartOutlinedIcon from "@mui/icons-material/ShoppingCartOutlined";
const Navbar = () => {
  const items = useSelector((state) => state.itemsSlice);
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const handlecheckout = () => {
    if (items.length < 2) {
      dispatch(
        setalert({
          open: true,
          message: "You need to add atleast 2 item in thali",
          type: "error",
        })
      );
    } else {
      navigate("/checkout");
    }
  };
  return (
    <nav
      className="navbar navbar-expand-lg bg-primary position-sticky"
      style={{ width: "100%" }}
    >
      <div className="container-fluid">
        <Link className="navbar-brand logo" to="/">
          <span style={{ fontWeight: "bold", fontSize: "26px", color: "gold" }}>
            King
          </span>
          Thali
        </Link>
        <button
          className="navbar-toggler"
          type="button"
          data-bs-toggle="collapse"
          data-bs-target="#navbarSupportedContent"
          aria-controls="navbarSupportedContent"
          aria-expanded="false"
          aria-label="Toggle navigation"
        >
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarSupportedContent">
          <ul className="navbar-nav me-auto mb-2 mb-lg-0"></ul>

          <span className="d-flex mx-4" role="search">
            {/* <input className="form-control me-2" type="search" placeholder="Search" aria-label="Search"/> */}
            <button
              className="btn btn-primary mx-3 "
              style={{ fontWeight: "bold", color: "white" }}
              onClick={() => navigate("/")}
            >
              HOME
            </button>
            <button
              className="btn btn-primary mx-3 "
              style={{ fontWeight: "bold", color: "white" }}
            >
              <ShoppingCartOutlinedIcon></ShoppingCartOutlinedIcon>
              {items.length}
            </button>

            <button
              className="btn btn-warning mx-3 "
              style={{ fontWeight: "bold", color: "white" }}
              onClick={handlecheckout}
            >
              CHECK OUT
            </button>
          </span>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
