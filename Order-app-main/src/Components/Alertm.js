
import {Snackbar } from "@mui/material";
import { useDispatch } from "react-redux";
import {useSelector} from "react-redux";
import {setalert} from "../Slices/alertSlice";
import Alert from '@mui/material/Alert';

const Alertm = () => {
  const dispatch = useDispatch();

const getalert=useSelector((state)=>state.AlertSlice)
  const handleCloseAlert = (event, reason) => {
    if (reason === "clickaway") {
      return;
    }

    dispatch(setalert({ open: false }));
  };

  return (
    <Snackbar
    className="snackbar"
      open={getalert.open}
      autoHideDuration={2000}
      onClose={handleCloseAlert}
    >
      <Alert
      className="snackbar"
        onClose={handleCloseAlert}
        elevation={10}
        variant="filled"
        severity={getalert.type}
      >
        {getalert.message}
      </Alert>
    </Snackbar>
    
  );
};

export default Alertm;
