const fs = require("fs");
const path = require("path");
const axios = require("axios");
const cheerio = require("cheerio");

(() => {
  try {
    const file = {};
    let json;

    const filePath = path.resolve(__dirname, "./foo1.json");
    Promise.all(
      fs.readFile(filePath, (err, data) => {
        if (err) throw err;
        else {
          json = JSON.parse(data);

          const jsonNumber = Object.keys(json).length;
          for (let i = 1; i < jsonNumber; i++) {
            const cveId = Object.values(json);
            if (cveId[i] !== "null" && cveId[i] !== "undefined") {
              cveId[i].map((cve) => {
                axios
                  .get(`https://www.cvedetails.com/cve/${cve}`)
                  .then((response) => {
                    const mainUrl = cheerio.load(response.data);
                    const detail = mainUrl.root().find("#cvedetails");
                    let desc = detail
                      .find("div.cvedetailssummary")
                      .text()
                      .trim();
                    desc = desc.split("\t\n")[0];
                    const cveScore = detail
                      .find(
                        "table#cvssscorestable tbody >:nth-child(1) > :nth-child(2)"
                      )
                      .text()
                      .trim();
                    const cveType = detail
                      .find(
                        "table#cvssscorestable tbody >:nth-child(8) > :nth-child(2)"
                      )
                      .text()
                      .trim();
                    // console.log(cveType);
                    const json = {
                      [cve]: {
                        score: cveScore,
                        type: cveType,
                        desc: desc,
                      },
                    };
                    console.log(json);
                    Object.assign(file, json);
                  })
                  .catch((err) => {
                    console.log(err);
                  });

                //   const mainUrl = cheerio.load(response.data);
                //   const detail = mainUrl.root().find("#cvedetails");
                //   const desc = detail.find("div.cvedetailssummary").text().trim();
                //   const cveScore = detail
                //     .find(
                //       "table#cvssscorestable tbody >:nth-child(1) > :nth-child(2)"
                //     )
                //     .text()
                //     .trim();
                //   const cveType = detail
                //     .find(
                //       "table#cvssscorestable tbody >:nth-child(8) > :nth-child(2)"
                //     )
                //     .text()
                //     .trim();
                //   // console.log(cveType);
                //   const json = {
                //     [cve]: {
                //       score: cveScore,
                //       type: cveType,
                //       desc: desc,
                //     },
                //   };
                //   console.log(json);
                //   Object.assign(file, json);
              });
            }
          }
        }
      })
    );
    setTimeout(() => {
      console.log(file);
      fs.writeFile("./cve_detail.json", JSON.stringify(file), (err) => {
        if (err) console.log(err);
        console.log("The file has been saved!");
      });
    }, 50000);
  } catch (e) {
    console.log(e.message);
  }
})();
